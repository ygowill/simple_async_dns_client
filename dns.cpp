#include "dns.h"
#include <fmt/format.h>
#include <tabulate.hpp>

#include <cstdio>
#include <string>
#include <sys/ioctl.h>
#include <assert.h>

using tabulate::FontAlign;
using tabulate::FontStyle;
using tabulate::Table;

namespace DNS {
    std::string IPBin2Dec(const std::string &data) {
        if (data.size() < 4) {
            return "";
        }
        char buf[32] = {0};
        snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
                 (unsigned char) data[0], (unsigned char) data[1],
                 (unsigned char) data[2], (unsigned char) data[3]);
        return buf;
    }

    void printSectionTag(const std::string &section_name) {
        fmt::print(
                "┌{0:─^{2}}┐\n"
                "│{1: ^{2}}│\n"
                "└{0:─^{2}}┘\n",
                "", section_name, 20);
    }

    void PrintBuffer(const char *buf, int len) {
        int width = 16;

        for (int i = 0; i < len; i++) {
            if (i % width == 0) {
                fmt::print("{:<5}", i / width);
            }
            char ch = ' ';
            if ((i + 1) % width == 0) {
                ch = '\n';
            }
            unsigned char byte = buf[i];
            int hi = 0x0f & (byte >> 4);
            int lo = 0x0f & byte;

            fmt::print("{:X}{:X}{}", hi, lo, ch);
        }
        fmt::print("\n");
    }

    int ParseUnsignedInt(const char *buf, int pos, int end, unsigned int &value) {
        value = 0;
        value = (unsigned char) buf[pos++];
        value = (value << 8) | (unsigned char) buf[pos++];
        value = (value << 8) | (unsigned char) buf[pos++];
        value = (value << 8) | (unsigned char) buf[pos++];
        return pos;
    }

    int ParseUnsignedShort(const char *buf, int pos, int end, uint16_t &value) {
        value = 0;
        value = (unsigned char) buf[pos++];
        value = (value << 8) | (unsigned char) buf[pos++];
        return pos;
    }

    int ParseHost(const char *buf, int pos, int end, std::string &host) {
        if (buf == nullptr) {
            return pos;
        }
        unsigned int limit = 0xc0;
        unsigned int len = (unsigned char) buf[pos++];
        while (len != 0 && !(len & limit)) {
            host.append(buf + pos, len);
            pos += len;
            len = (unsigned char) buf[pos++];
            if (len != 0) {
                host.append(".");
            }
        }
        if (len & limit) {
            unsigned int offset = ((limit ^ len) << 8) | (unsigned char) buf[pos++];
            ParseHost(buf, offset, end, host);
        }
        return pos;
    }

    int ParseQuestionSection(const char *buf, int pos, int end, DNS::DnsQuestionSection &dns_question_section) {
        pos = ParseHost(buf, pos, end, dns_question_section.host);
        pos = ParseUnsignedShort(buf, pos, end, dns_question_section.query_type);
        pos = ParseUnsignedShort(buf, pos, end, dns_question_section.query_class);
        return pos;
    }

    int ParseResourceRecord(const char *buf, int pos, int end, DNS::DnsResource &dns_resource) {
        if (buf == NULL) {
            return pos;
        }
        pos = ParseHost(buf, pos, end, dns_resource.host);
        pos = ParseUnsignedShort(buf, pos, end, dns_resource.domain_type);
        pos = ParseUnsignedShort(buf, pos, end, dns_resource.domain_class);
        pos = ParseUnsignedInt(buf, pos, end, dns_resource.ttl);
        pos = ParseUnsignedShort(buf, pos, end, dns_resource.data_len);
        dns_resource.data_pos = pos;
        pos += dns_resource.data_len;
        return pos;
    }

    int ParseDnsRecordDataField(const char *buf, int pos, int end, DNS::DnsResource &res) {
        uint16_t type = res.domain_type;
        if (type == 1) {
            res.data = IPBin2Dec(std::string(buf + res.data_pos, res.data_len));
        } else if (type == 2 || type == 5) {
            ParseHost(buf, res.data_pos, end, res.data);
        } else if (type == 28) {
            res.data = "IPV6 ADDR";
        } else {
            res.data = "OTHERS";
        }
        return 0;
    }

    int ParseDnsResponsePacket(const char *buf, int end) {
        if (buf == nullptr) {
            return -1;
        }

        // get current terminal col size
        struct winsize w {};
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        int win_size = w.ws_col;


        int pos = 0;
        // query transaction id
        uint16_t query_id = 0;
        query_id = buf[pos++];
        query_id = (query_id << 8) | buf[pos++];

        bool req_recursive = false;
        uint16_t opcode_info = 0;
        // |qr| opcode |aa|tc|rd|
        pos = ParseUnsignedShort(buf, pos, end, opcode_info);
        if (opcode_info & 0x0f) {
            fmt::print("dns ret code non-zero, ret = {}\n", opcode_info & 0x0f);
            return -1;
        }

        int table_width = 160;
        int subtable_width = table_width - 10;
        bool table_flag = win_size > table_width;
        fmt::print("window columns={}{}{}, enbale_table={}\n", win_size, table_flag ? ">" : "<", table_width, table_flag);

        // generate data table
        Table dns_package;
        dns_package.format().font_style({FontStyle::bold}).font_align(FontAlign::center).width(table_width);
        dns_package.add_row({"DNS Response Package"});

        //============header section=================
        std::string response_state = opcode_info & 0x80 ? "true" : "false";

        uint16_t query_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, query_cnt);

        uint16_t answer_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, answer_cnt);

        uint16_t authority_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, authority_cnt);

        uint16_t additional_cnt = 0;
        pos = ParseUnsignedShort(buf, pos, end, additional_cnt);

        if (!table_flag) {
            printSectionTag("header section");
            fmt::print("query id: {}\nrecursived response: {}\nquery_cnt: {}\nanswer_cnt: {}\nauthority_cnt: {}\naddtional_cnt: {}\n",
                       query_id,
                       response_state,
                       query_cnt,
                       answer_cnt,
                       authority_cnt,
                       additional_cnt);
        }

        Table header;
        header.format().font_style({FontStyle::bold}).font_align(FontAlign::center).width(subtable_width);
        header.add_row({"response header"});
        Table header_section;
        header_section.add_row({"query id", "recursived response", "query_cnt", "answer_cnt", "authority_cnt", "addtional_cnt"});
        header_section.add_row({std::to_string(query_id), response_state, std::to_string(query_cnt), std::to_string(answer_cnt), std::to_string(authority_cnt), std::to_string(additional_cnt)});
        header.add_row({header_section});
        header[1].format().hide_border_top();
        dns_package.add_row({header});
        dns_package[1].format().hide_border_top();


        //============query section=================
        Table query;
        query.format().font_style({FontStyle::bold}).font_align(FontAlign::center).width(subtable_width);
        query.add_row({"query section"});
        Table query_section;
        query_section.add_row({"host", "type", "class"});
        if (!table_flag) {
            printSectionTag("query section");
        }

        for (int i = 0; i < query_cnt; i++) {
            DNS::DnsQuestionSection dns_question;
            pos = ParseQuestionSection(buf, pos, end, dns_question);
            query_section.add_row({dns_question.host, std::to_string(dns_question.query_type), std::to_string(dns_question.query_class)});
            if (!table_flag) {
                fmt::print("host: {} type: {} class: {}\n", dns_question.host, dns_question.query_type, dns_question.query_class);
            }
        }

        query.add_row({query_section});
        query[1].format().hide_border_top();
        dns_package.add_row({query});
        dns_package[2].format().hide_border_top();


        //===========answer section=================
        Table answer;
        answer.format().font_style({FontStyle::bold}).font_align(FontAlign::center).width(subtable_width);
        answer.add_row({"answer section"});
        Table answer_section;
        answer_section.add_row({fmt::format("{:<55}", "host"), "type", "class", "ttl", "dlen", fmt::format("{:<55}", "data")});
        if (!table_flag) {
            printSectionTag("answer section");
        }


        for (int i = 0; i < answer_cnt; i++) {
            DNS::DnsResource res;
            pos = ParseResourceRecord(buf, pos, end, res);
            ParseDnsRecordDataField(buf, pos, end, res);
            answer_section.add_row({res.host, std::to_string(res.domain_type), std::to_string(res.domain_class), std::to_string(res.ttl), std::to_string(res.data_len), res.data});
            if (!table_flag) {
                fmt::print("host={}, type={}, class={}, ttl={}, dlen={}, data={}\n",
                           res.host,
                           res.domain_type,
                           res.domain_class,
                           res.ttl,
                           res.data_len,
                           res.data);
            }
        }
        answer.add_row({answer_section});
        answer[1].format().hide_border_top();
        dns_package.add_row({answer});
        dns_package[3].format().hide_border_top();


        //==========authority section==============
        Table authority;
        authority.format().font_style({FontStyle::bold}).font_align(FontAlign::center).width(subtable_width);
        authority.add_row({"authority section"});
        tabulate::Table authority_section;
        authority_section.add_row({fmt::format("{:<55}", "host"), "type", "class", "ttl", "dlen", fmt::format("{:<55}", "data")});
        if (!table_flag) {
            printSectionTag("authority section");
        }


        for (int i = 0; i < authority_cnt; i++) {
            DNS::DnsResource res;
            pos = ParseResourceRecord(buf, pos, end, res);
            ParseDnsRecordDataField(buf, pos, end, res);
            authority_section.add_row({res.host, std::to_string(res.domain_type), std::to_string(res.domain_class), std::to_string(res.ttl), std::to_string(res.data_len), res.data});
            if (!table_flag) {
                fmt::print("host={}, type={}, class={}, ttl={}, dlen={}, data={}\n",
                           res.host,
                           res.domain_type,
                           res.domain_class,
                           res.ttl,
                           res.data_len,
                           res.data);
            }
        }
        authority.add_row({authority_section});
        authority[1].format().hide_border_top();
        dns_package.add_row({authority});
        dns_package[4].format().hide_border_top();

        //==========additional section=============
        Table additional;
        additional.format().font_style({FontStyle::bold}).font_align(FontAlign::center).width(subtable_width);
        additional.add_row({"additional section"});
        tabulate::Table additional_section;
        additional.format().hide_border_top();
        additional_section.add_row({fmt::format("{:<55}", "host"), "type", "class", "ttl", "dlen", fmt::format("{:<55}", "data")});
        if (!table_flag) {
            printSectionTag("additional section");
        }

        for (int i = 0; i < additional_cnt; i++) {
            DNS::DnsResource res;
            pos = ParseResourceRecord(buf, pos, end, res);
            ParseDnsRecordDataField(buf, pos, end, res);
            additional_section.add_row({res.host, std::to_string(res.domain_type), std::to_string(res.domain_class), std::to_string(res.ttl), std::to_string(res.data_len), res.data});
            if (!table_flag) {
                fmt::print("host={}, type={}, class={}, ttl={}, dlen={}, data={}\n",
                           res.host,
                           res.domain_type,
                           res.domain_class,
                           res.ttl,
                           res.data_len,
                           res.data);
            }
        }

        if (table_flag) {
            additional.add_row({additional_section});
            dns_package.add_row({additional});
            dns_package[5].format().hide_border_top();
            std::cout << dns_package << std::endl;
        }
        return 0;
    }

    //  header format
    //   0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |                      ID                       |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |QR|  opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |                    QDCOUNT                    |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |                    ANCOUNT                    |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |                    NSCOUNT                    |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    //  |                    ARCOUNT                    |
    //  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


    int BuildDnsQueryPacket(const char *host, char *buf, int pos, int end) {
        if (buf == nullptr || host == nullptr) {
            return 0;
        }
        //==========header section===========
        // query id
        uint16_t query_id = 0x091d;
        buf[pos++] = 0xff & (query_id >> 8);
        buf[pos++] = 0xff & query_id;

        bool req_recursive = true;
        // |qr| opcode |aa|tc|rd|
        buf[pos++] = req_recursive ? 0x01 : 0x00;
        // |ra|z|rcode|
        buf[pos++] = 0x00;

        // QDCOUNT
        uint16_t query_cnt = 0x0001;
        buf[pos++] = 0xff & (query_cnt >> 8);
        buf[pos++] = 0xff & query_cnt;

        // ANCOUNT
        buf[pos++] = 0;
        buf[pos++] = 0;

        // NSCOUNT
        buf[pos++] = 0;
        buf[pos++] = 0;

        // ARCOUNT
        buf[pos++] = 0;
        buf[pos++] = 0;

        //==========query section========
        int cp = 0;
        char ch = 0;
        char last = 0;
        int lp = pos++;
        while ((ch = host[cp++]) != '\0' && pos < end) {
            if (ch != '.') {
                buf[pos++] = ch;
                last = ch;
                continue;
            }
            int len = pos - lp - 1;
            if (len <= 0 || len > 63) {
                fmt::print("host name format invalid.\n");
                return -1;
            }
            buf[lp] = len;
            lp = pos++;
        }
        if (last == '.') {
            buf[lp] = 0;
        } else {
            buf[lp] = pos - lp - 1;
            buf[pos++] = 0;
        }

        //==========query type==========
        uint16_t query_type = 0x0001;
        buf[pos++] = 0xff & (query_type >> 8);
        buf[pos++] = 0xff & query_type;

        //==========query class=========
        uint16_t query_class = 0x0001;
        buf[pos++] = 0xff & (query_class >> 8);
        buf[pos++] = 0xff & query_class;

        return pos;
    }

} /* end of namespace DNS */