#include "stream_parser.h"
#include "util.h"

stream_parser::stream_parser(const pcre *url_filter_re, const pcre_extra *url_filter_extra,
                             const std::string &output_path) :
        url_filter_re(url_filter_re),
        url_filter_extra(url_filter_extra),
        output_path(output_path),
        gzip_response_flag(false),
        gzip_request_flag(false),
        dump_flag(-1) {
    std::memset(&next_seq, 0, sizeof next_seq);
    std::memset(&ts_usc, 0, sizeof ts_usc);
    std::memset(&fin_nxtseq, 0, sizeof fin_nxtseq);
    http_parser_init(&parser[HTTP_REQUEST], HTTP_REQUEST);
    parser[HTTP_REQUEST].data = this;
    http_parser_init(&parser[HTTP_RESPONSE], HTTP_RESPONSE);
    parser[HTTP_RESPONSE].data = this;

    http_parser_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_message_begin = on_message_begin;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;
    settings.on_headers_complete = on_headers_complete;
    settings.on_body = on_body;
    settings.on_message_complete = on_message_complete;
}

bool stream_parser::parse(const struct packet_info &packet, enum http_parser_type type) {
    std::string *str = NULL;
    size_t orig_size = raw[type].size();
    str = &raw[type];
    if (next_seq[type] != 0 && packet.seq != next_seq[type]) {
        if (packet.seq < next_seq[type]) {
            // retransmission packet
            if (packet.is_rst || is_stream_fin(packet, type)) {
                dump_http_request();
                return false;
            }
            return true;
        } else {
            // out-of-order packet
            out_of_order_packet[type].insert(
                    std::make_pair(packet.seq, std::make_pair(packet.body, packet.nxtseq)));
        }
    } else {
        str->append(packet.body);
        next_seq[type] = packet.nxtseq;
    }
    while (!out_of_order_packet[type].empty()) {
        const std::map<uint32_t, std::pair<std::string, uint32_t> >::iterator &iterator =
                out_of_order_packet[type].find(next_seq[type]);
        if (iterator == out_of_order_packet[type].end()) break;
        str->append(iterator->second.first);
        next_seq[type] = iterator->second.second;
        out_of_order_packet[type].erase(iterator);
    }

    bool ret = true;
    if (str->size() > orig_size) {
        last_ts_usc = packet.ts_usc;
        size_t parse_bytes = http_parser_execute(&parser[type], &settings, str->c_str() + orig_size,
                                                 str->size() - orig_size);
        ret = parse_bytes > 0 && HTTP_PARSER_ERRNO(&parser[type]) == HPE_OK;
    }
    if (packet.is_rst || is_stream_fin(packet, type)) {
        dump_http_request();
        return false;
    }
    return ret;
}

void stream_parser::set_addr(const std::string &req_addr, const std::string &resp_addr) {
    this->address[HTTP_REQUEST].assign(req_addr);
    this->address[HTTP_RESPONSE].assign(resp_addr);
}

int stream_parser::on_message_begin(http_parser *parser) {
    stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
    if (parser->type == HTTP_REQUEST) {
        self->ts_usc[parser->type] = self->last_ts_usc;
    }
    self->dump_flag = 0;
    return 0;
}

int stream_parser::on_url(http_parser *parser, const char *at, size_t length) {
    stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
    self->url.assign(at, length);
    self->method.assign(http_method_str(static_cast<enum http_method>(parser->method)));
    if (!self->match_url(self->url)) {
        return -1;
    }
    return 0;
};

int stream_parser::on_header_field(http_parser *parser, const char *at, size_t length) {
    stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
    self->temp_header_field.assign(at, length);
    for (size_t i = 0; i < length; ++i) {
        if (at[i] >= 'A' && at[i] <= 'Z') {
            self->temp_header_field[i] = at[i] ^ (char) 0x20;
        }
    }
    return 0;
}

int stream_parser::on_header_value(http_parser *parser, const char *at, size_t length) {
    stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
    if (parser->type == HTTP_RESPONSE) {
        if (self->temp_header_field == "content-encoding" && std::strstr(at, "gzip")) {
            self->gzip_response_flag = true;
        }
    } else if (parser->type == HTTP_REQUEST) {
        if (self->temp_header_field == "content-encoding" && std::strstr(at, "gzip")) {
            self->gzip_request_flag = true;
        }
    } else {
        if (self->temp_header_field == "host") {
            self->host.assign(at, length);
        }
    }
    // std::cout << self->temp_header_field <<  ":" << std::string(at, length) << std::endl;
    return 0;
}

int stream_parser::on_headers_complete(http_parser *parser) {
    if (parser->type == HTTP_REQUEST || parser->type == HTTP_RESPONSE) {
        stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
        self->header[parser->type] = self->raw[parser->type].substr(0, parser->nread);
        if (parser->type == HTTP_RESPONSE) {
            self->ts_usc[parser->type] = self->last_ts_usc;
        }
    }
    return 0;
}

int stream_parser::on_body(http_parser *parser, const char *at, size_t length) {
    if (parser->type == HTTP_REQUEST || parser->type == HTTP_RESPONSE) {
        stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
        self->body[parser->type].append(at, length);
        if (parser->type == HTTP_RESPONSE) {
            self->ts_usc[parser->type] = self->last_ts_usc;
        }
    }
    return 0;
}

int stream_parser::on_message_complete(http_parser *parser) {
    stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
    if (parser->type == HTTP_RESPONSE) {
        if (parser->type == HTTP_RESPONSE && parser->status_code == HTTP_STATUS_CONTINUE) {
            self->header_100_continue.assign(self->header[HTTP_RESPONSE]);
            self->body_100_continue.assign(self->body[HTTP_RESPONSE]);
            self->raw[HTTP_RESPONSE].clear();
            self->body[HTTP_RESPONSE].clear();
            // reset response parser
            http_parser_init(parser, HTTP_RESPONSE);
        } else {
            self->ts_usc[parser->type] = self->last_ts_usc;
            self->dump_http_request();
        }
    }
    return 0;
}

bool stream_parser::match_url(const std::string &url) {
    if (!url_filter_re) return true;
    int ovector[30];
    int rc = pcre_exec(url_filter_re, url_filter_extra, url.c_str(), url.size(), 0, 0, ovector, 30);
    return rc >= 0;
}

void stream_parser::dump_http_request() {
    if (dump_flag != 0) return;

    if (gzip_response_flag && !body[HTTP_RESPONSE].empty()) {
        std::string new_body;
        if (gzip_decompress(body[HTTP_RESPONSE], new_body)) {
            body[HTTP_RESPONSE].assign(new_body);
        } else {
            std::cerr << ANSI_COLOR_RED << "[decompress error]" << ANSI_COLOR_RESET << std::endl;
        }
    }

    std::cout << ANSI_COLOR_CYAN << address[HTTP_REQUEST] << " -> " << address[HTTP_RESPONSE];
    if (!host.empty()) {
        std::cout << " " << ANSI_COLOR_GREEN << host << ANSI_COLOR_CYAN;
    }
    std::size_t i = url.find('?');
    std::string url_no_query = i == std::string::npos ? url : url.substr(0, i);
    std::cout << " " << url_no_query << ANSI_COLOR_RESET;

    char buff[128];
    if (ts_usc[HTTP_RESPONSE] && ts_usc[HTTP_REQUEST]) {
        if (ts_usc[HTTP_REQUEST] % 1000000 == 0 && ts_usc[HTTP_RESPONSE] % 1000000 == 0) {
            std::snprintf(buff, 128, " cost %lu ", (ts_usc[HTTP_RESPONSE] - ts_usc[HTTP_REQUEST]) / 1000000);
        } else {
            std::snprintf(buff, 128, " cost %.6f ", (ts_usc[HTTP_RESPONSE] - ts_usc[HTTP_REQUEST]) / 1000000.0);
        }
        std::cout << buff;
    }

    if (!output_path.empty()) {
        static size_t req_idx = 0;
        std::snprintf(buff, 128, "/%p.%lu", this, ++req_idx);
        std::string save_filename = output_path;
        save_filename.append(buff);
        std::cout << " saved at " << save_filename << std::endl;
        std::ofstream out(save_filename.c_str(), std::ios::app | std::ios::out);
        if (out.is_open()) {
            out << *this << std::endl;
            out.close();
        } else {
            std::cerr << "ofstream [" << save_filename << "] is not opened." << std::endl;
            out.close();
            exit(1);
        }
    } else {
        std::cout << std::endl << *this << std::endl;
    }
    // clear
    raw[HTTP_REQUEST] = std::string();
    raw[HTTP_RESPONSE] = std::string();
    body[HTTP_REQUEST] = std::string();
    body[HTTP_RESPONSE] = std::string();
    header_100_continue.clear();
    body_100_continue.clear();
    host.clear();
    std::memset(&ts_usc, 0, sizeof ts_usc);
    gzip_response_flag = false;
    gzip_request_flag = false;
    dump_flag = 1;
}

bool stream_parser::is_stream_fin(const struct packet_info &packet, enum http_parser_type type) {
    // three-way handshake
    if (packet.is_fin) {
        fin_nxtseq[type] = packet.nxtseq;
        return false;
    } else {
        return fin_nxtseq[HTTP_REQUEST] && fin_nxtseq[HTTP_RESPONSE] && packet.ack == fin_nxtseq[!type];
    }
}

std::ostream &operator<<(std::ostream &out, const stream_parser &parser) {
    out << ANSI_COLOR_GREEN
        << parser.header[HTTP_REQUEST]
        << ANSI_COLOR_RESET;
    if (!parser.header_100_continue.empty()) {
        out << ANSI_COLOR_BLUE
            << parser.header_100_continue
            << ANSI_COLOR_RESET;
    }
    if (!parser.body_100_continue.empty()) {
        out << parser.body_100_continue;
    }
    if(parser.gzip_request_flag) {
        std::string non_const_request_body;
        std::string new_body;
        non_const_request_body.assign(parser.body[HTTP_REQUEST]);
        if (gzip_decompress(non_const_request_body, new_body)) {
            out << new_body;
        } else {
            out << ANSI_COLOR_RED << "[decompress error]" << ANSI_COLOR_RESET << std::endl;
        }

    } else if (!is_atty || is_plain_text(parser.body[HTTP_REQUEST])) {
        out << parser.body[HTTP_REQUEST];
    } else {
        out << ANSI_COLOR_RED << "[binary request body] (size:" << parser.body[HTTP_REQUEST].size() << ")"
            << ANSI_COLOR_RESET;
    }
    out << std::endl
        << ANSI_COLOR_BLUE
        << parser.header[HTTP_RESPONSE]
        << ANSI_COLOR_RESET;
    if (parser.body[HTTP_RESPONSE].empty()) {
        out << ANSI_COLOR_RED << "[empty response body]" << ANSI_COLOR_RESET;
    } else if (!is_atty || is_plain_text(parser.body[HTTP_RESPONSE])) {
        out << parser.body[HTTP_RESPONSE];
    } else {
        out << ANSI_COLOR_RED << "[binary response body] (size:" << parser.body[HTTP_RESPONSE].size() << ")"
            << ANSI_COLOR_RESET;
    }
    out << std::endl;
    return out;
}

std::ofstream &operator<<(std::ofstream &out, const stream_parser &parser) {
    out << parser.header[HTTP_REQUEST]
        << parser.header_100_continue
        << parser.body_100_continue
        << parser.body[HTTP_REQUEST]
        << parser.header[HTTP_RESPONSE]
        << parser.body[HTTP_RESPONSE];
    return out;
}
