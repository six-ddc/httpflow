#include "stream_parser.h"
#include "util.h"

stream_parser::stream_parser(const pcre *url_filter_re, const pcre_extra *url_filter_extra,
                             const std::string &output_path) :
        url_filter_re(url_filter_re),
        url_filter_extra(url_filter_extra),
        output_path(output_path),
        gzip_flag(false) {
    next_seq[HTTP_REQUEST] = 0;
    next_seq[HTTP_RESPONSE] = 0;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = this;

    http_parser_settings_init(&settings);
    settings.on_url = on_url;
    settings.on_header_field = on_header_field;
    settings.on_header_value = on_header_value;
    settings.on_headers_complete = on_headers_complete;
    settings.on_body = on_body;
    settings.on_message_complete = on_message_complete;
}

bool stream_parser::parse(const struct packet_info &packet, enum http_parser_type type) {
    if (parser.type != type) {
        http_parser_init(&parser, type);
    }
    size_t orig_size = 0;
    std::string *str = NULL;
    if (parser.type == HTTP_REQUEST || parser.type == HTTP_RESPONSE) {
        orig_size = raw[parser.type].size();
        str = &raw[parser.type];
        if (next_seq[parser.type] != 0 && packet.seq != next_seq[parser.type]) {
            if (packet.seq < next_seq[parser.type]) {
                // retransmission packet
                return true;
            } else {
                // out-of-order packet
                out_of_order_packet[parser.type].insert(std::make_pair(packet.seq, packet.body));
            }
        } else {
            str->append(packet.body);
            next_seq[parser.type] = packet.seq + packet.body.size();
        }
        while (!out_of_order_packet[parser.type].empty()) {
            const std::map<uint32_t, std::string>::iterator &iterator =
                    out_of_order_packet[parser.type].find(next_seq[parser.type]);
            if (iterator != out_of_order_packet[parser.type].end()) {
                str->append(iterator->second);
                next_seq[parser.type] += iterator->second.size();
                out_of_order_packet[parser.type].erase(iterator);
            } else {
                break;
            }
        }
    }

    if (str->size() > orig_size) {
        size_t parse_bytes = http_parser_execute(&parser, &settings, str->c_str() + orig_size, str->size() - orig_size);
        return parse_bytes > 0 && HTTP_PARSER_ERRNO(&parser) == HPE_OK;
    }
    return true;
}

void stream_parser::set_addr(const std::string &req_addr, const std::string &resp_addr) {
    this->address[HTTP_REQUEST] = req_addr;
    this->address[HTTP_RESPONSE] = resp_addr;
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
            self->gzip_flag = true;
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
    }
    return 0;
}

int stream_parser::on_body(http_parser *parser, const char *at, size_t length) {
    if (parser->type == HTTP_REQUEST || parser->type == HTTP_RESPONSE) {
        stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
        self->body[parser->type].append(at, length);
    }
    return 0;
}

int stream_parser::on_message_complete(http_parser *parser) {
    stream_parser *self = reinterpret_cast<stream_parser *>(parser->data);
    if (parser->type == HTTP_RESPONSE) {
        if (self->gzip_flag && !self->body[HTTP_RESPONSE].empty()) {
            std::string new_body;
            if (gzip_decompress(self->body[HTTP_RESPONSE], new_body)) {
                self->body[HTTP_RESPONSE] = new_body;
            } else {
                std::cerr << ANSI_COLOR_RED << "[decompress error]" << ANSI_COLOR_RESET << std::endl;
            }
        }
        self->save_http_request();
    }
    return 0;
}

bool stream_parser::match_url(const std::string &url) {
    if (!url_filter_re) return true;
    int ovector[30];
    int rc = pcre_exec(url_filter_re, url_filter_extra, url.c_str(), url.size(), 0, 0, ovector, 30);
    return rc >= 0;
}

void stream_parser::save_http_request() {
    std::cout << ANSI_COLOR_CYAN << address[HTTP_REQUEST] << " -> " << address[HTTP_RESPONSE]
              << ANSI_COLOR_RESET << std::endl;
    if (!output_path.empty()) {
        std::string save_filename = output_path + "/" + host;
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
        std::cout << *this << std::endl;
    }
    // clear
    raw[HTTP_REQUEST] = std::string();
    raw[HTTP_RESPONSE] = std::string();
    body[HTTP_REQUEST] = std::string();
    body[HTTP_RESPONSE] = std::string();
}

std::ostream &operator<<(std::ostream &out, const stream_parser &parser) {
    out << ANSI_COLOR_GREEN
        << parser.header[HTTP_REQUEST]
        << ANSI_COLOR_RESET;
    if (!is_atty || is_plain_text(parser.body[HTTP_REQUEST])) {
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
    return out;
}

std::ofstream &operator<<(std::ofstream &out, const stream_parser &parser) {
    out << parser.header[HTTP_REQUEST]
        << parser.body[HTTP_REQUEST]
        << parser.header[HTTP_RESPONSE]
        << parser.body[HTTP_RESPONSE];
    return out;
}
