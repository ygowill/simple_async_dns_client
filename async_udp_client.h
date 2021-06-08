#ifndef DNS_CLIENT_ASYNC_UDP_CLIENT_H
#define DNS_CLIENT_ASYNC_UDP_CLIENT_H

#include "asio.hpp"
#include "dns.h"
#include <fmt/format.h>
#include <iostream>
#include <string>
#include <utility>

using asio::ip::udp;
using std::string;

class async_udp_client {
public:
    explicit async_udp_client()
        : sock_(s_ios, udp::endpoint(udp::v4(), 0)),
          s_end_point(asio::ip::address::from_string(DNS::DEFAULT_DNS_SERVER_IP), DNS::DNS_UDP_PORT),
          read_buf_{0},
          write_buf_{0}
    {}

    explicit async_udp_client(const string& host)
        : sock_(s_ios, udp::endpoint(udp::v4(), 0)),
          s_end_point(asio::ip::address::from_string(host), DNS::DNS_UDP_PORT),
          read_buf_{0},
          write_buf_{0}
    {}

    virtual ~async_udp_client() = default;

public:
    void query(const string& url, bool verbose=false) {
        query_url = url;
        v_ = verbose;
        do_write(query_url);
        s_ios.run();
    }

private:
    void on_read(const asio::error_code &err, size_t bytes) {
        if (!err) {
            if (v_) {
                fmt::print("{0:=^{1}}\n", "", 80);
                fmt::print("DNS Response Packet {} bytes\n", bytes);
                DNS::PrintBuffer(read_buf_, bytes);
                fmt::print("{0:=^{1}}\n", "", 80);
            }
            DNS::ParseDnsResponsePacket(read_buf_, bytes);
        } else {
            fmt::print(stderr, "error code: {}\n", err.value());
            fmt::print(stderr, "error value: {}\n", err.message());
        }
    }

    void do_read() {
        sock_.async_receive_from(asio::buffer(read_buf_), sender_end_point_, [this](auto && PH1, auto && PH2) { on_read(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
    }

    void on_write(const asio::error_code &err, size_t bytes) {
        do_read();
    }

    void do_write(const string &url) {
        int len = build_query(url);
        sock_.async_send_to(asio::buffer(write_buf_, len), s_end_point, [this](auto && PH1, auto && PH2) { on_write(std::forward<decltype(PH1)>(PH1), std::forward<decltype(PH2)>(PH2)); });
    }

    int build_query(const string& url) {
        int len = DNS::BuildDnsQueryPacket(url.c_str(), write_buf_, 0, s_buff_size);
        if (len < 0) {
            fmt::print(stderr, "build dns query packet fail.\n");
            exit(1);
        } else {
            if (v_) {
                fmt::print("{0:=^{1}}\n", "", 80);
                fmt::print("DNS Query Pakcet {} bytes\n", len);
                DNS::PrintBuffer(write_buf_, len);
                fmt::print("{0:=^{1}}\n", "", 80);
            }
        }
        return len;
    }

private:
    static const size_t s_buff_size = 1024;
    udp::endpoint s_end_point;
    bool v_ = false;

private:
    udp::socket sock_;
    udp::endpoint sender_end_point_;
    char read_buf_[s_buff_size];
    char write_buf_[s_buff_size];
    string query_url;

public:
    static asio::io_service s_ios;
};


asio::io_service async_udp_client::s_ios;

#endif//DNS_CLIENT_ASYNC_UDP_CLIENT_H
