#ifndef custom_parser_h
#define custom_parser_h

#include <iostream>
#include <fstream>
#include <string>
#include <pcre.h>
#include <map>
#include "http_parser.h"

class custom_parser {

    friend std::ofstream &operator<<(std::ofstream &out, const custom_parser &f);

    friend std::ostream &operator<<(std::ostream &out, const custom_parser &f);

private:
    const pcre *url_filter_re;
    const pcre_extra *url_filter_extra;
    const std::string &output_path;

    http_parser parser;
    http_parser_settings settings;

    std::string method;
    std::string url;

    std::string address[HTTP_BOTH];
    std::string raw[HTTP_BOTH];
    std::string header[HTTP_BOTH];
    std::string body[HTTP_BOTH];
    uint32_t next_seq[HTTP_BOTH];
    std::map<uint32_t, std::string> out_of_order_packet[HTTP_BOTH];

    std::string temp_header_field;
    bool gzip_flag;
    std::string host;

public:
    custom_parser(const pcre *url_filter_re, const pcre_extra *url_filter_extra, const std::string &output_path);

    bool parse(const struct packet_info &body, enum http_parser_type type);

    std::string get_response_body() const;

    inline bool is_request_address(const std::string &addr) const {
        return address[HTTP_REQUEST] == addr;
    }

    void set_addr(const std::string &req_addr, const std::string &resp_addr);

    bool match_url(const std::string &url);

    void save_http_request();

    static int on_url(http_parser *parser, const char *at, size_t length);

    static int on_header_field(http_parser *parser, const char *at, size_t length);

    static int on_header_value(http_parser *parser, const char *at, size_t length);

    static int on_headers_complete(http_parser *parser);

    static int on_body(http_parser *parser, const char *at, size_t length);

    static int on_message_complete(http_parser *parser);
};

std::ostream &operator<<(std::ostream &out, const custom_parser &parser);

std::ofstream &operator<<(std::ofstream &out, const custom_parser &parser);

#endif
