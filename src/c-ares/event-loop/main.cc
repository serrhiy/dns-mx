#include <print>
#include <iostream>
#include <unordered_map>
#include <string>

#include <ares.h>

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

int main(const int argc, const char* argv[]) {
  ares_channel_t* channel;
  ares_options options;
  int optmask = 0;
  options.evsys = ARES_EVSYS_DEFAULT;
  optmask = ARES_OPT_EVENT_THREAD;

  if (int status = ares_init_options(&channel, &options, optmask); status != ARES_SUCCESS) {
    const std::string& message = STATUS_TO_MESSAGE.at(static_cast<ares_status_t>(status));
    std::print(std::cerr, "Error occurred during initialization c-ares: {}\n", message);
    return -1;
  }
  ares_query_dnsrec(channel, "gmail.com", ARES_CLASS_IN, ARES_REC_TYPE_MX, callback, nullptr, nullptr);
  ares_queue_wait_empty(channel, -1);
  ares_destroy(channel);
  return 0;
}
