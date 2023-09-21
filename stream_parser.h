#ifndef custom_parser_h
#define custom_parser_h

#include <iostream>
#include <fstream>
#include <string>
#include <pcre.h>
#include <map>
#include "http_parser.h"

class stream_parser {

    friend std::ofstream &operator<<(std::ofstream &out, const stream_parser &f);

    friend std::ostream &operator<<(std::ostream &out, const stream_parser &f);

private:
    const pcre *url_filter_re;
    const pcre_extra *url_filter_extra;
    const std::string &output_path;

    http_parser_settings settings;

    std::string method;
    std::string url;
    std::string host;

    long last_ts_usc;
    long ts_usc[HTTP_BOTH];
    http_parser parser[HTTP_BOTH];
    std::string address[HTTP_BOTH];
    std::string raw[HTTP_BOTH];
    std::string header[HTTP_BOTH];
    std::string body[HTTP_BOTH];
    uint32_t next_seq[HTTP_BOTH];
    std::map<uint32_t, std::pair<std::string, uint32_t> > out_of_order_packet[HTTP_BOTH];

    std::string header_100_continue;
    std::string body_100_continue;

    std::string temp_header_field;
    bool gzip_response_flag;
    bool gzip_request_flag;
    int dump_flag;

    uint32_t fin_nxtseq[HTTP_BOTH];

public:
    stream_parser(const pcre *url_filter_re, const pcre_extra *url_filter_extra, const std::string &output_path);

    bool parse(const struct packet_info &packet, enum http_parser_type type);

    inline bool is_request_address(const std::string &addr) const {
        return address[HTTP_REQUEST] == addr;
    }

    void set_addr(const std::string &req_addr, const std::string &resp_addr);

    bool match_url(const std::string &url);

    void dump_http_request();

    bool is_stream_fin(const struct packet_info &packet, enum http_parser_type type);

    static int on_message_begin(http_parser *parser);

    static int on_url(http_parser *parser, const char *at, size_t length);

    static int on_header_field(http_parser *parser, const char *at, size_t length);

    static int on_header_value(http_parser *parser, const char *at, size_t length);

    static int on_headers_complete(http_parser *parser);

    static int on_body(http_parser *parser, const char *at, size_t length);

    static int on_message_complete(http_parser *parser);
};

std::ostream &operator<<(std::ostream &out, const stream_parser &parser);

std::ofstream &operator<<(std::ofstream &out, const stream_parser &parser);

#endif
