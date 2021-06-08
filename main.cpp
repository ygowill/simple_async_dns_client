#include "async_udp_client.h"
#include <cmdline.h>

#include <sys/ioctl.h>
#include <string>

using namespace std;

int main(int argc, char* argv[]) {
    string url;
    string dns_server;
    bool verbose;

    cmdline::parser parser;
    parser.add<string>("url", 'u', "query url", false);
    parser.add<string>("server", 's', "dns server", false, "114.114.114.114");
    parser.add("verbose", 'v', "dns packet verbose info");
    parser.add("help", 'h', "usage instruction");
    parser.add("check", 'c', "check your terminal window size");
    parser.add("tips", '\0', "you can expand your terminal window width upto 160 for the fancy output~");

    parser.parse_check(argc, argv);

    if (parser.exist("check")) {
        struct winsize w {};
        ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
        fmt::print("window size:\nrows={}\ncolumns={}\n", w.ws_row, w.ws_col);
        return 0;
    }

    url = parser.get<string>("url");
    if (url.empty()) {
        fmt::print(stderr, "If you don't use the -c parameter, you have to use -u for dns querying.\n");
        fmt::print(stderr, parser.usage());
        return -1;
    }
    dns_server = parser.get<string>("server");
    verbose = parser.exist("verbose");
    if(verbose) {
        fmt::print("query url: {} \ndns server: {}\n", url, dns_server);
    }

    async_udp_client client(dns_server);
    client.query(url, verbose);

    return 0;
}