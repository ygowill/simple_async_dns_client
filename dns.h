#ifndef DNS_CLIENT_DNS_H
#define DNS_CLIENT_DNS_H

#include <string>

namespace DNS {

    typedef struct tagDnsQuestionSection {
        std::string host;
        unsigned short query_type;
        unsigned short query_class;
    } DnsQuestionSection;

    typedef struct tagDnsResource {
        std::string host;
        unsigned short domain_type;
        unsigned short domain_class;
        unsigned int ttl;
        unsigned short data_len;
        unsigned short data_pos;
        std::string data;// parsed
    } DnsResource;

    const static unsigned short DNS_UDP_PORT = 53;
    const static std::string DEFAULT_DNS_SERVER_IP = "114.114.114.114";

    void PrintBuffer(const char *buf, int len);
    int BuildDnsQueryPacket(const char *host, char *buf, int pos, int end);
    int ParseDnsResponsePacket(const char *buf, int end);

}
#endif//DNS_CLIENT_DNS_H
