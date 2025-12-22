#include <print>
#include <vector>
#include <future>
#include <map>

#include <ares.h>
#include <boost/asio.hpp>

#include "defer.hh"

struct MxRecord {
  std::string hostname;
  short preference;
};

constexpr int DEFAULT_TIMEOUT = 2000;

class MxResolver {
  using wait_type = boost::asio::posix::descriptor_base::wait_type;

  ares_channel_t* channel;
  boost::asio::any_io_executor executor;
  boost::asio::steady_timer timeout_timer;
  std::map<int, boost::asio::posix::stream_descriptor> fds;

  static void socketStateCallback(void *data, ares_socket_t fd, int readable, int writable) {
    MxResolver* resolver = reinterpret_cast<MxResolver*>(data);
    auto callback = std::bind(&MxResolver::onSocketEvent, resolver, fd, readable != 0, writable != 0);
    boost::asio::post(resolver->executor, std::move(callback));
  }

  void updateTimer() {
    using namespace boost::asio::chrono;

    struct timeval tv;
    ares_timeout(channel, nullptr, &tv);
    timeout_timer.cancel();
    timeout_timer.expires_after(seconds{ tv.tv_sec } + microseconds{ tv.tv_usec });
    timeout_timer.async_wait([this](const boost::system::error_code& err) {
      if (!err) {
        ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
      }
    });
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
    auto callback = std::bind(&MxResolver::asyncSocketEvent, this, boost::asio::placeholders::error, fd, type);
    descriptor->second.async_wait(type, std::move(callback));
  }

  void onSocketEvent(int fd, bool readable, bool writable) {
    if (!readable && !writable) {
      const auto descriptor = fds.find(fd);
      if (descriptor != fds.end()) {
        fds.erase(descriptor);
      }
      return;
    }

    updateTimer();

    auto& descriptor = fds.try_emplace(fd, executor, fd).first->second;
    if (readable) {
      descriptor.async_wait(wait_type::wait_read, [this, fd](const boost::system::error_code& err) {
        asyncSocketEvent(err, fd, wait_type::wait_read);
      });
    }
    if (writable) {
      descriptor.async_wait(wait_type::wait_write, [this, fd](const boost::system::error_code& err) {
        asyncSocketEvent(err, fd, wait_type::wait_write);
      });
    }
    descriptor.async_wait(wait_type::wait_error, [this, fd](const boost::system::error_code& err) {
      asyncSocketEvent(err, fd, wait_type::wait_error);
    });
  }

  static void processResponse(void* arg, ares_status_t status, size_t timeouts, const ares_dns_record_t* dnsrec) {
    auto promise = reinterpret_cast<std::promise<std::vector<MxRecord>>*>(arg);
    utils::defer defer{ [promise](){ delete promise; } };
    if (status == ARES_ENODATA || status == ARES_ENOTFOUND) {
      promise->set_value({});
      return;
    }
    if (status != ARES_SUCCESS) {
      auto exception = std::make_exception_ptr(std::runtime_error(ares_strerror(status)));
      promise->set_exception(exception);
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
    promise->set_value(std::move(records));
  }

  public:
  explicit MxResolver(boost::asio::any_io_executor executor, int timeout = DEFAULT_TIMEOUT):
      channel{ nullptr }, executor{ executor }, timeout_timer{ executor } {
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

  std::future<std::vector<MxRecord>> request(std::string_view domain) {
    auto promise = new std::promise<std::vector<MxRecord>>;
    auto future = promise->get_future();
    ares_query_dnsrec(channel, domain.data(), ARES_CLASS_IN, ARES_REC_TYPE_MX, processResponse, promise, nullptr);
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
