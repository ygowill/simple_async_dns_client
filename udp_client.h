#ifndef DNS_CLIENT_UDP_CLIENT_H
#define DNS_CLIENT_UDP_CLIENT_H

#include <asio.hpp>
#include <iostream>

using asio::ip::udp;

class UDPClient {
public:
    asio::io_service io_service;
    udp::socket socket;
    udp::endpoint endpoint;
    char buf[1024];

    UDPClient();
    void do_receive();
    void handle_receive(const asio::error_code &error, size_t);
};

UDPClient::UDPClient()
    : io_service(),
      socket(io_service, {udp::v4(), 8888}) {
    do_receive();
    io_service.run();
}

void UDPClient::do_receive() {
    socket.async_receive_from(asio::buffer(buf), endpoint,
                              boost::bind(&UDPClient::handle_receive, this,
                                          asio::placeholders::error,
                                          asio::placeholders::bytes_transferred));
}

void UDPClient::handle_receive(const asio::error_code &error, size_t bytes_transferred) {
    std::cout << "ulala" << std::endl;
    std::cout << "Received: '" << std::string(buf) << "'\n";

    if (!error || error == asio::error::message_size)
        do_receive();
}

#endif//DNS_CLIENT_UDP_CLIENT_H
