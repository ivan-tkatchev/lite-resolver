
#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <functional>
#include <netinet/in.h>
#include <stdexcept>
#include <stdio.h>  //printf
#include <string.h> //strlen
#include <sys/socket.h>
#include <unistd.h> //getpid

#include "resolver.hh"

#ifdef DEBUG_ON
#define DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

namespace {

struct SocketRAII {
  template <typename... Args> explicit SocketRAII(Args &&...args) {
    fd = socket(std::forward<Args>(args)...);
  }

  operator int() const { return fd; }
  ~SocketRAII() { ::close(fd); }

  int fd;
};

bool check_ipv4(const std::string &host) {
  unsigned char ip_address[sizeof(struct in6_addr)];
  return inet_pton(AF_INET, host.c_str(), ip_address) > 0;
}
/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
std::string get_dns_servers() {
  std::string dns_server;
  FILE *fp;
  char line[200], *p;
  if ((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
    DEBUG("Failed opening /etc/resolv.conf file \n");
  }

  while (fgets(line, 200, fp)) {
    if (line[0] == '#') {
      continue;
    }
    if (strncmp(line, "nameserver", 10) == 0) {
      p = strtok(line, " ");
      p = strtok(NULL, " ");
      DEBUG("Nameserver=%s", p);
      dns_server = p;
    }
  }
  if (dns_server.empty()) {
    dns_server = "208.67.222.222";
  }

  return dns_server;
}

bool ChangetoDnsNameFormat(unsigned char* dns, const unsigned char* buf_end, std::string host) {
  size_t lock = 0, i;
  host.push_back('.');

  for (i = 0; i < host.size(); i++) {
      if (dns >= buf_end - 1) {
          return false;
      }

      if (host[i] == '.') {
          *dns++ = i - lock;
          for (; lock < i; lock++) {
              *dns++ = host[lock];
          }
          lock++; // or lock=i+1;
      }
  }
  *dns++ = '\0';
  return true;
}

std::string ReadName(const unsigned char *reader, const unsigned char *buffer, int *count) {
  std::string name;
  name.reserve(256);
  bool jumped = false;

  *count = 0;

  // read the names in 3www6google3com format
  while (*reader != 0) {
      if ((*reader & 0xC0) == 0xC0) {
          size_t offset = ((*reader) * 256 + *(reader + 1)) & (~0xc000); // 49152 = 11000000 00000000 ;)
          reader = buffer + offset;
          *count += 2;
          jumped = true;
      } else {
          unsigned int len = *reader;

          for (unsigned int j = 0; j < len; ++j) {
              ++reader;
              name.push_back(*reader);
          }
          ++reader;

          name.push_back('.');

          if (!jumped) {
              *count += len + 1;
          }
      }
  }

  if (name.size() > 0) {
      name.pop_back();
  }

  return name;
}

} // namespace

namespace http::dns {
// DNS header structure
struct DNS_HEADER {
  unsigned short id; // identification number

  unsigned char rd : 1;     // recursion desired
  unsigned char tc : 1;     // truncated message
  unsigned char aa : 1;     // authoritive answer
  unsigned char opcode : 4; // purpose of message
  unsigned char qr : 1;     // query/response flag

  unsigned char rcode : 4; // response code
  unsigned char cd : 1;    // checking disabled
  unsigned char ad : 1;    // authenticated data
  unsigned char z : 1;     // its z! reserved
  unsigned char ra : 1;    // recursion available

  unsigned short q_count;    // number of question entries
  unsigned short ans_count;  // number of answer entries
  unsigned short auth_count; // number of authority entries
  unsigned short add_count;  // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION {
  uint16_t qtype;
  uint16_t qclass;
};

// Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA {
  unsigned short type;
  unsigned short _class;
  unsigned int ttl;
  unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD {
  struct R_DATA *resource;
  std::string name;
  std::string rdata;
};

// Structure of a Query
typedef struct {
  unsigned char *name;
  struct QUESTION *ques;
} QUERY;

/*
 * Perform a DNS query by sending a packet
 * */
DNS resolve_dns(const std::string &host, DNSRecords query_type,
                size_t timeout_sec, size_t timeout_micro) {
  constexpr size_t kBufSize = 65536;
  constexpr auto kIncorrectReponseMessage =
      "Incorrect response: buffer out of range";

  DNS result;
  if (check_ipv4(host)) {
    result.ipv4 = {host};
    return result;
  }
  static std::string dns_server = get_dns_servers();

  unsigned char buf[kBufSize], *qname, *reader;
  int stop;

  const auto* buf_end = &buf[kBufSize - 1];

  struct sockaddr_in a;

  struct RES_RECORD answers[20], auth[20], addit[20]; // the replies from the DNS server
  struct sockaddr_in dest;

  struct DNS_HEADER *dns = NULL;
  struct QUESTION *qinfo = NULL;

  DEBUG("Resolving %s", host.c_str());

  SocketRAII s(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP packet for DNS queries

  if (s < 0) {
      perror("socket() failed");
      return result;
  }

  struct timeval timeout;
  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = timeout_micro;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));

  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);
  dest.sin_addr.s_addr = inet_addr(dns_server.c_str()); // dns servers

  // Set the DNS structure to standard queries
  dns = (struct DNS_HEADER *)&buf;

  dns->id = (unsigned short)htons(getpid());
  dns->qr = 0;     // This is a query
  dns->opcode = 0; // This is a standard query
  dns->aa = 0;     // Not Authoritative
  dns->tc = 0;     // This message is not truncated
  dns->rd = 1;     // Recursion Desired
  dns->ra = 0;     // Recursion not available! hey we dont have it (lol)
  dns->z = 0;
  dns->ad = 0;
  dns->cd = 0;
  dns->rcode = 0;
  dns->q_count = htons(1); // we have only 1 question
  dns->ans_count = 0;
  dns->auth_count = 0;
  dns->add_count = 0;

  // point to the query portion
  qname = (unsigned char *)&buf[sizeof(struct DNS_HEADER)];

  if (!ChangetoDnsNameFormat(qname, buf_end, host)) {
      return result;
  }

  qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1)];

  if ((const unsigned char*)qinfo + sizeof(struct QUESTION) > buf_end) {
      return result;
  }

  qinfo->qtype = (size_t)htons(static_cast<uint16_t>(query_type)); // type of the query , A , MX , CNAME , NS etc
  qinfo->qclass = (size_t)htons(1); // its internet (lol)

  DEBUG("\nSending Packet...");
  if (sendto(s, (char *)buf,
             sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(struct QUESTION),
             0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {

      perror("sendto() failed");
      return result;
  }
  DEBUG("Done");

  // Receive the answer
  int i = sizeof dest;
  DEBUG("\nReceiving answer...");
  if (recvfrom(s, (char *)buf, kBufSize, 0, (struct sockaddr *)&dest, (socklen_t *)&i) < 0) {

      perror("recvfrom() failed");
      return result;
  }
  DEBUG("Done");

  dns = (struct DNS_HEADER *)buf;

  // move ahead of the dns header and the query field
  reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(struct QUESTION)];

  DEBUG("\nThe response contains : ");
  DEBUG("\n %d Questions.", ntohs(dns->q_count));
  DEBUG("\n %d Answers.", ntohs(dns->ans_count));
  DEBUG("\n %d Authoritative Servers.", ntohs(dns->auth_count));
  DEBUG("\n %d Additional records.\n\n", ntohs(dns->add_count));

  // Start reading answers
  stop = 0;

  for (int i = 0; i < ntohs(dns->ans_count); i++) {
    answers[i].name = ReadName(reader, buf, &stop);
    reader = reader + stop;

    answers[i].resource = (struct R_DATA *)(reader);
    reader = reader + sizeof(struct R_DATA);
    if (reader > buf_end) {
      throw std::runtime_error(kIncorrectReponseMessage);
    }

    DEBUG("  Ans: %d\n", ntohs(answers[i].resource->type));
    if (static_cast<DNSRecords>(ntohs(answers[i].resource->type)) == DNSRecords::T_A) // if its an ipv4 address
    {
        answers[i].rdata = std::string(reader,
                                       reader + static_cast<size_t>(ntohs(answers[i].resource->data_len)));

        reader = reader + answers[i].rdata.size();
        if (reader > buf_end) {
            throw std::runtime_error(kIncorrectReponseMessage);
        }

        long* p;
        p = (long *)answers[i].rdata.data();
        a.sin_addr.s_addr = (*p); // working without ntohl
        DEBUG("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        result.ipv4.push_back(inet_ntoa(a.sin_addr));

    } else {
        answers[i].rdata = ReadName(reader, buf, &stop);
        reader = reader + stop;
        if (reader > buf_end) {
            throw std::runtime_error(kIncorrectReponseMessage);
        }

        if (static_cast<DNSRecords>(ntohs(answers[i].resource->type)) == DNSRecords::T_CNAME) {
            DEBUG("has alias name : %s", answers[i].rdata.c_str());
            result.ipv4_aliases.push_back(answers[i].rdata);
        }
    }
  }

  return result;
}

} // namespace http::dns
