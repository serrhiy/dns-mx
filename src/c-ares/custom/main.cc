#include <print>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <ranges>

#include <poll.h>

#include <ares.h>

struct DnsState {
  ares_channel_t                *channel;
  std::vector<struct pollfd>    fds;
  std::vector<ares_fd_events_t> events;
};

const std::unordered_map<ares_status_t, std::string> STATUS_TO_MESSAGE {
  { ARES_SUCCESS,        "Operation completed successfully" },

  { ARES_EFILE,          "Failed to read configuration file" },
  { ARES_ENOMEM,         "Memory was exhausted" },
  { ARES_ENOTINITIALIZED,"Library not initialized" },
  { ARES_ENOSERVER,      "No DNS servers are configured" },

  { ARES_ENODATA,        "The query completed but contains no answers" },
  { ARES_EFORMERR,       "The server reported a malformed query" },
  { ARES_ESERVFAIL,      "The server experienced an internal failure" },
  { ARES_ENOTFOUND,      "The domain name does not exist (NXDOMAIN)" },
  { ARES_ENOTIMP,        "The requested DNS operation is not implemented by the server" },
  { ARES_EREFUSED,       "The DNS server refused the query" },

  { ARES_EBADNAME,       "The domain name is invalid or cannot be encoded" },
  { ARES_ETIMEOUT,       "No DNS servers responded within the timeout period" },
  { ARES_ECONNREFUSED,   "No DNS servers could be contacted" },
  { ARES_ECANCELLED,     "The query was cancelled" },
  { ARES_EDESTRUCTION,   "The channel is being destroyed; the query was aborted" }
};

void callback(void* arg, ares_status_t status, size_t timeouts, const ares_dns_record_t* dnsrec) {
  const std::string& message = STATUS_TO_MESSAGE.at(static_cast<ares_status_t>(status));
  std::print("Response received, status: {}\n", message);
  if (status != ARES_SUCCESS) return;
  const size_t count = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  const char* name;
  ares_dns_record_query_get(dnsrec, 0, &name, nullptr, nullptr);
  for (size_t index = 0; index < count; index++) {
    ares_dns_rr_t* record = ares_dns_record_rr_get(const_cast<ares_dns_record_t*>(dnsrec), ARES_SECTION_ANSWER, index);
    const char* mx = ares_dns_rr_get_str(record, ARES_RR_MX_EXCHANGE);
    const short preference = ares_dns_rr_get_u16(record, ARES_RR_MX_PREFERENCE);
    std::print("Domain: {}, MX: {}, Preference: {}\n", name, mx, preference);
  }
}

void sock_state_callback(void *data, ares_socket_t socket_fd, int readable, int writable) {
  using std::ranges::find_if;

  DnsState* state = static_cast<DnsState*>(data);
  const auto iterator = find_if(state->fds, [socket_fd](const auto& p) { return p.fd == socket_fd; });

  if (!readable && !writable) {
    if (iterator != state->fds.end()) {
      state->fds.erase(iterator);
    }
    return;
  }

  short events = 0;
  if (readable) events |= POLLIN;
  if (writable) events |= POLLOUT;

  if (iterator == state->fds.end()) {
    state->fds.push_back({ socket_fd, events, 0 });
  } else {
    iterator->events = events;
  }
}

void process(DnsState& state) {
  struct timeval tv;
  while (true) {
    if (ares_timeout(state.channel, NULL, &tv) == NULL) {
      break;
    }

    const int timeout = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    const int rv = poll(state.fds.data(), state.fds.size(), timeout);
    if (rv < 0) {
      continue;
    } else if (rv == 0) {
      ares_process_fd(state.channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
      continue;
    }

    state.events.clear();
    for (size_t index = 0; index < state.fds.size(); index++) {
      const struct pollfd& descriptor = state.fds[index];
      if (descriptor.revents == 0) continue;
      unsigned events = 0;
      if (descriptor.revents & (POLLERR | POLLHUP | POLLIN)) {
        events |= ARES_FD_EVENT_READ;
      }
      if (descriptor.revents & POLLOUT) {
        events |= ARES_FD_EVENT_WRITE;
      }
      ares_fd_events_t event{ descriptor.fd, events };
      state.events.push_back(event);
    }

    ares_process_fds(state.channel, state.events.data(), state.events.size(), ARES_PROCESS_FLAG_NONE);
  }
}

int main(const int argc, const char* argv[]) {
  ares_channel_t* channel;
  DnsState state;
  ares_options options{ .sock_state_cb = sock_state_callback, .sock_state_cb_data = &state };
  int optmask = ARES_OPT_SOCK_STATE_CB;
  if (int status = ares_init_options(&channel, &options, optmask); status != ARES_SUCCESS) {
    const std::string& message = STATUS_TO_MESSAGE.at(static_cast<ares_status_t>(status));
    std::print(std::cerr, "Error occurred during initialization c-ares: {}\n", message);
    return -1;
  }
  state.channel = channel;
  ares_query_dnsrec(channel, "gmail.com", ARES_CLASS_IN, ARES_REC_TYPE_MX, callback, nullptr, nullptr);
  process(state);
  ares_destroy(channel);
  return 0;
}
