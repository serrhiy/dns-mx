#include <print>
#include <vector>
#include <future>
#include <map>
#include <functional>
#include <memory>

#include <ares.h>
#include <boost/asio.hpp>

struct MxRecord {
  std::string hostname;
  short preference;
};

constexpr int DEFAULT_TIMEOUT = 2000;

class MxResolver {
  using wait_type = boost::asio::posix::descriptor_base::wait_type;
  using result_t = std::vector<MxRecord>;
  using callback_t = std::function<void(std::exception_ptr, result_t)>;

  ares_channel_t* channel;
  boost::asio::strand<boost::asio::any_io_executor> strand;
  boost::asio::steady_timer timeout_timer;
  std::map<int, boost::asio::posix::stream_descriptor> fds;

  static void socketStateCallback(void *data, ares_socket_t fd, int readable, int writable) {
    MxResolver* resolver = reinterpret_cast<MxResolver*>(data);
    boost::asio::dispatch(resolver->strand, [resolver, fd, readable, writable]() {
      resolver->onSocketEvent(fd, readable != 0, writable != 0);
    });
  }

  void updateTimer() {
    timeout_timer.cancel();
    struct timeval tv;
    if (ares_timeout(channel, nullptr, &tv) == nullptr) {
      return;
    }

    timeout_timer.expires_after(std::chrono::seconds{ tv.tv_sec } +
                                std::chrono::microseconds{ tv.tv_usec });

    timeout_timer.async_wait(boost::asio::bind_executor(strand, 
      [this](const boost::system::error_code& err) {
        if (!err) {
          ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
          updateTimer();
        }
      }));
  }

  void asyncSocketEvent(const boost::system::error_code& err, int fd, wait_type type) {
    using boost::asio::posix::stream_descriptor;

    const auto descriptor = fds.find(fd);
    if (err || descriptor == fds.end()) {
      return;
    }
    const int read_fd = type == wait_type::wait_write ? ARES_SOCKET_BAD : fd;
    const int write_fd = type == wait_type::wait_write ? fd : ARES_SOCKET_BAD;
    ares_process_fd(channel, read_fd, write_fd);
    updateTimer();
    if (type != wait_type::wait_error) {
      startAsyncWait(fd, type);
    }
  }

  void startAsyncWait(int fd, wait_type type) {
    const auto descriptor = fds.find(fd);
    if (descriptor == fds.end()) {
      return;
    }
    descriptor->second.async_wait(type, boost::asio::bind_executor(strand,
      [this, fd, type](const boost::system::error_code& err) {
        asyncSocketEvent(err, fd, type);
      }));
  }

  void onSocketEvent(int fd, bool readable, bool writable) {
    if (!readable && !writable) {
      const auto descriptor = fds.find(fd);
      if (descriptor != fds.end()) {
        fds.erase(descriptor);
      }
      return;
    }

    auto& descriptor = fds.try_emplace(fd, strand.get_inner_executor(), fd).first->second;
    updateTimer();
    
    if (readable) {
      startAsyncWait(fd, wait_type::wait_read);
    }
    if (writable) {
      startAsyncWait(fd, wait_type::wait_write);
    }
    startAsyncWait(fd, wait_type::wait_error);
  }

  static void processResponse(void* arg, ares_status_t status, size_t timeouts, const ares_dns_record_t* dnsrec) {
    std::unique_ptr<callback_t> callback{ reinterpret_cast<callback_t*>(arg) };
    if (status == ARES_ENODATA || status == ARES_ENOTFOUND) {
      callback->operator()(nullptr, {});
      return;
    }
    if (status != ARES_SUCCESS) {
      auto exception = std::make_exception_ptr(std::runtime_error(ares_strerror(status)));
      callback->operator()(exception, {});
      return;
    }
    const size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
    const char* name;
    ares_dns_record_query_get(dnsrec, 0, &name, nullptr, nullptr);
    std::vector<MxRecord> records;
    for (size_t index = 0; index < count; index++) {
      ares_dns_rr_t* record = ares_dns_record_rr_get(const_cast<ares_dns_record_t*>(dnsrec), ARES_SECTION_ANSWER, index);
      const short preference = ares_dns_rr_get_u16(record, ARES_RR_MX_PREFERENCE);
      const char* mx = ares_dns_rr_get_str(record, ARES_RR_MX_EXCHANGE);
      if (mx != NULL) {
        records.push_back(MxRecord{mx, preference});
      }
    }
    callback->operator()(nullptr, std::move(records));
  }

  public:
  explicit MxResolver(boost::asio::any_io_executor executor, int timeout = DEFAULT_TIMEOUT):
      channel{ nullptr }, strand{ executor }, timeout_timer{ executor } {
    ares_options options{ .timeout = timeout, .sock_state_cb = socketStateCallback, .sock_state_cb_data = this };
    int optmask = ARES_OPT_SOCK_STATE_CB | ARES_OPT_TIMEOUTMS;
    if (int status = ares_init_options(&channel, &options, optmask); status != ARES_SUCCESS) {
      throw std::runtime_error{ ares_strerror(status) };
    }
  }

  MxResolver() = delete;

  MxResolver(const MxResolver&) = delete;
  MxResolver& operator=(const MxResolver&) = delete;

  MxResolver(MxResolver&&) = delete;
  MxResolver& operator=(MxResolver&&) = delete;

  void request(std::string_view domain, callback_t callback) {
    auto fn = new callback_t{ std::move(callback) };
    ares_query_dnsrec(channel, domain.data(), ARES_CLASS_IN, ARES_REC_TYPE_MX, processResponse, fn, nullptr);
  }

  std::future<result_t> request(std::string_view domain) {
    auto promise = std::make_shared<std::promise<result_t>>();
    auto future = promise->get_future();
    request(domain, [promise](std::exception_ptr exception, result_t result) {
      if (exception) {
        promise->set_exception(exception);
        return;
      }
      promise->set_value(std::move(result));
    });
    return future;
  }

  ~MxResolver() {
    ares_destroy(channel);
  }
};

int main(const int argc, const char* argv[]) {
  boost::asio::io_context io_context;
  MxResolver resolver{ io_context.get_executor() };
  
  const std::vector<std::string> domains{ "gmail.com", "jci.com", "outlook.com" };

  // for (const std::string& domain: domains) {
  //   resolver.request(domain, [](std::exception_ptr exception, std::vector<MxRecord> result) {
  //     if (exception) {
  //       std::println("error occured");
  //     }
  //     for (const auto& [hostname, preference]: result) {
  //       std::println("Mx: {}, Preference: {}", hostname, preference);
  //     }
  //   });
  // }
  // io_context.run();

  std::vector<std::future<std::vector<MxRecord>>> futures;
  for (const std::string& domain: domains) {
    futures.push_back(resolver.request(domain));
  }
  io_context.run();
  for (auto& future: futures) {
    for (const auto& [hostname, preference]: future.get()) {
      std::println("Mx: {}, Preference: {}", hostname, preference);
    }
  }
  return 0;
}
