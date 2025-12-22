#include <print>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <ranges>
#include <future>
#include <map>

#include <ares.h>
#include <boost/asio.hpp>

#include "defer.hh"

struct MxRecord {
  std::string hostname;
  short preference;
};

class MxResolver {
  ares_channel_t* channel;
  boost::asio::any_io_executor executor;
  std::map<int, boost::asio::posix::stream_descriptor> fds;

  static void socketStateCallback(void *data, ares_socket_t fd, int readable, int writable) {
    MxResolver* resolver = reinterpret_cast<MxResolver*>(data);
    auto callback = std::bind(&MxResolver::onSocketEvent, resolver, fd, readable != 0, writable != 0);
    boost::asio::dispatch(resolver->executor, std::move(callback));
  }

  void onSocketEvent(int fd, bool readable, bool writable) {
    using boost::asio::posix::stream_descriptor::wait_read;
    using boost::asio::posix::stream_descriptor::wait_write;

    if (!readable && !writable) {
      if (fds.contains(fd)) {
        fds.erase(fd);
      }
      return;
    }

    auto& descriptor = fds.try_emplace(fd, executor, fd).first->second;
    if (readable) {
      descriptor.async_wait(wait_read, [this, fd](const boost::system::error_code& err) {
        if (!err) {
          ares_process_fd(channel, fd, ARES_SOCKET_BAD);
        }
      });
    }
    if (writable) {
      descriptor.async_wait(wait_write, [this, fd](const boost::system::error_code& err) {
        if (!err) {
          ares_process_fd(channel, ARES_SOCKET_BAD, fd);
        }
      });
    }
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
      const char* mx = ares_dns_rr_get_str(record, ARES_RR_MX_EXCHANGE);
      const short preference = ares_dns_rr_get_u16(record, ARES_RR_MX_PREFERENCE);
      records.push_back(MxRecord{mx, preference});
    }
    promise->set_value(std::move(records));
  }

  public:
  explicit MxResolver(boost::asio::any_io_executor executor): channel{ nullptr }, executor{ executor } {
    ares_options options{ .sock_state_cb = socketStateCallback, .sock_state_cb_data = this };
    int optmask = ARES_OPT_SOCK_STATE_CB;
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
    auto promise = new std::promise<std::vector<MxRecord>>{};
    ares_query_dnsrec(channel, domain.data(), ARES_CLASS_IN, ARES_REC_TYPE_MX, processResponse, promise, nullptr);
    return promise->get_future();
  }

  ~MxResolver() {
    ares_destroy(channel);
  }
};

int main(const int argc, const char* argv[]) {
  boost::asio::io_context io_context;
  MxResolver resolver{ io_context.get_executor() };
  auto future = resolver.request("gmail.com1");
  io_context.run();
  const auto records = future.get();
  if (records.empty()) {
    std::print("No records found for such domain\n");
  }
  for (const auto [hostname, preference]: records) {
    std::print("MX: {}, Preference: {}\n", hostname, preference);
  }
  return 0;
}
