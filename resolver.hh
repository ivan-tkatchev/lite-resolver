#pragma once

#include <string>
#include <vector>
namespace http::dns {
/**
 * @brief DNS Resolver
 * The function allows you to get IP by timeout for the specified host.
 */
struct DNS {
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv4_aliases;
};

// Types of DNS resource records
enum class DNSRecords : uint16_t {
    T_A     = 1,   // Ipv4 address
    T_NS    = 2,   // Nameserver
    T_CNAME = 5,   // canonical name
    T_SOA   = 6,   /* start of authority zone */
    T_PTR   = 12,  /* domain name pointer */
    T_MX    = 15,  // Mail server
};

DNS resolve_dns(const std::string& host, DNSRecords query_type, size_t timeout_sec, size_t timeout_micro);

}  // namespace http::dns
