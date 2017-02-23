#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <memory.h>
#include <stdlib.h>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sstream>
#include <list>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <zlib.h>
#include "http_parser.h"

#define USE_ANSI_COLOR

#ifdef USE_ANSI_COLOR

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#else

#define ANSI_COLOR_RED     ""
#define ANSI_COLOR_GREEN   ""
#define ANSI_COLOR_YELLOW  ""
#define ANSI_COLOR_BLUE    ""
#define ANSI_COLOR_MAGENTA ""
#define ANSI_COLOR_CYAN    ""
#define ANSI_COLOR_RESET   ""

#endif  // USE_ANSI_COLOR

#define CRLF "\r\n"
#define MAXIMUM_SNAPLEN 262144

struct capture_config {
#define IFNAMSIZ    16
    int snaplen;
    unsigned short port;
    std::string output_path;
    char device[IFNAMSIZ];
    std::string filter;
};

struct packet_info {
    std::string src_addr;
    std::string dst_addr;

    std::string body;
};

class custom_parser {

    friend std::ofstream& operator<<(std::ofstream& out, const custom_parser& f);
    friend std::ostream& operator<<(std::ostream& out, const custom_parser& f);

private:
    http_parser parser;
    http_parser_settings settings;

    std::string method;
    std::string url;

    std::string request_address;
    std::string response_address;

    std::string request;
    std::string request_header;
    std::string request_body;

    bool request_complete_flag;

    std::string response;
    std::string response_header;
    std::string response_body;

    bool response_complete_flag;

    std::string temp_header_field;
    bool gzip_flag;
    std::string host;

public:
    custom_parser();

    bool parse(const std::string &body, enum http_parser_type type);

    std::string get_response_body() const;

    inline bool is_response_complete() const {
        return response_complete_flag;
    }

    inline bool is_request_complete() const {
        return request_complete_flag;
    }

    inline std::string get_host() const {
        return host;
    }

    inline std::string get_url() const {
        return url;
    }

    inline bool is_request_address(const std::string &address) const {
        return request_address == address;
    }

    void set_addr(const std::string &src_addr, const std::string &dst_addr);

    static int on_url(http_parser *parser, const char *at, size_t length);

    static int on_header_field(http_parser *parser, const char *at, size_t length);

    static int on_header_value(http_parser *parser, const char *at, size_t length);

    static int on_headers_complete(http_parser *parser);

    static int on_body(http_parser *parser, const char *at, size_t length);

    static int on_message_complete(http_parser *parser);
};

std::ostream& operator<<(std::ostream& out, const custom_parser& parser) {
    out
        << ANSI_COLOR_GREEN
        << parser.request_header
        << ANSI_COLOR_RESET
        << parser.request_body
        << std::endl
        << ANSI_COLOR_BLUE
        << parser.response_header
        << ANSI_COLOR_RESET
        << parser.response_body;
    return out;
}

std::ofstream& operator<<(std::ofstream& out, const custom_parser& parser) {
    out
        << parser.request_header
        << parser.request_body
        << parser.response_header
        << parser.response_body;
    return out;
}

std::map<std::string, std::list<custom_parser *> > http_requests;

static void get_join_addr(const std::string &src_addr, const std::string &dst_addr, std::string &ret) {
    if (src_addr < dst_addr) {
        ret = src_addr + "-" + dst_addr;
    } else {
        ret = dst_addr + "-" + src_addr;
    }
}

static std::string timeval2tr(const struct timeval *ts) {
    struct tm *local_tm = localtime(&ts->tv_sec);
    std::string time_str;
    time_str.resize(15);
    sprintf(&time_str[0], "%02d:%02d:%02d.%06d", local_tm->tm_hour, local_tm->tm_min, local_tm->tm_sec, ts->tv_usec);
    return time_str;
}

#define GZIP_CHUNK 16384

static bool gzip_decompress(std::string &src, std::string &dst) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    // gzip
    if (inflateInit2(&zs, 16 + MAX_WBITS) != Z_OK) {
        return false;
    }

    zs.next_in = reinterpret_cast<Bytef *>(&src[0]);
    zs.avail_in = src.size();

    int ret;
    char outbuffer[GZIP_CHUNK];

    do {
        zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
        zs.avail_out = sizeof(outbuffer);
        ret = inflate(&zs, 0);
        if (dst.size() < zs.total_out) {
            dst.append(outbuffer, zs.total_out - dst.size());
        }
    } while (ret == Z_OK);
    inflateEnd(&zs);
    return ret == Z_STREAM_END;
}

static std::string urlencode(const std::string &s) {
    static const char lookup[] = "0123456789abcdef";
    std::stringstream e;
    for (const char c : s) {
        if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
            (c == '-' || c == '_' || c == '.' || c == '~')) {
            e << c;
        } else {
            e << '%';
            e << lookup[(c & 0xF0) >> 4];
            e << lookup[(c & 0x0F)];
        }
    }
    return e.str();
}

struct tcphdr {
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;         /* sequence number */
    uint32_t th_ack;         /* acknowledgement number */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_offx2;       /* data offset, rsvd */
/* TCP flags */
#define TH_FIN     0x01
#define TH_SYN     0x02
#define TH_RST     0x04
#define TH_PUSH    0x08
#define TH_ACK     0x10
#define TH_URG     0x20
#define TH_ECNECHO 0x40 /* ECN Echo */
#define TH_CWR     0x80 /* ECN Cwnd Reduced */
    uint8_t th_flags;
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};

static bool process_tcp(struct packet_info *packet, const u_char *content, size_t len) {
    if (len < sizeof(struct tcphdr)) {
        std::cerr << "received truncated TCP datagram." << std::endl;
        return false;
    }
    auto tcp_header = reinterpret_cast<const struct tcphdr *>(content);

    size_t tcp_header_len = TH_OFF(tcp_header) << 2;
    if (len < tcp_header_len) {
        std::cerr << "received truncated TCP datagram." << std::endl;
        return false;
    }

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    packet->src_addr.append(":" + std::to_string(src_port));
    packet->dst_addr.append(":" + std::to_string(dst_port));

    /*
    std::cout<<"( " ANSI_COLOR_CYAN;
    if (tcp_header->th_flags & TH_FIN) {
        std::cout<<"FIN ";
    }
    if (tcp_header->th_flags & TH_SYN) {
        std::cout<<"SYN ";
    }
    if (tcp_header->th_flags & TH_RST) {
        std::cout<<"RST ";
    }
    if (tcp_header->th_flags & TH_PUSH) {
        std::cout<<"PUSH ";
    }
    if (tcp_header->th_flags & TH_ACK) {
        std::cout<<"ACK ";
    }
    if (tcp_header->th_flags & TH_URG) {
        std::cout<<"URG ";
    }
    if (tcp_header->th_flags & TH_ECE) {
        std::cout<<"ECE ";
    }
    if (tcp_header->th_flags & TH_CWR) {
        std::cout<<"CWR ";
    }
    std::cout<<ANSI_COLOR_RESET " Ack=" << tcp_header->th_ack << " Seq=" << tcp_header->th_seq << std::endl;
    std::string time_str = timeval2tr(&header->ts);
    std::cout<<"Time: " ANSI_COLOR_BLUE << time_str << ANSI_COLOR_RESET " Ip: "
        << packet->src_addr << " -> " << packet->dst_addr << " Join: " << packet->join_addr << std::endl;
    */

    content += tcp_header_len;
    packet->body = std::string(reinterpret_cast<const char *>(content), len - tcp_header_len);
    return true;
}

struct ip {
    uint8_t ip_vhl;     /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    uint8_t ip_tos;     /* type of service */
    uint16_t ip_len;     /* total length */
    uint16_t ip_id;      /* identification */
    uint16_t ip_off;     /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    uint8_t ip_ttl;     /* time to live */
    uint8_t ip_p;       /* protocol */
    uint16_t ip_sum;     /* checksum */
    uint32_t ip_src, ip_dst;  /* source and dest address */
};

static bool process_ipv4(struct packet_info *packet, const u_char *content, size_t len) {
    if (len < sizeof(struct ip)) {
        std::cerr << "received truncated IP datagram." << std::endl;
        return false;
    }
    auto ip_header = reinterpret_cast<const struct ip *>(content);
    if (4 != IP_V(ip_header) || ip_header->ip_p != IPPROTO_TCP) {
        return false;
    }
    size_t ip_header_len = IP_HL(ip_header) << 2;
    size_t ip_len = ntohs(ip_header->ip_len);

    char src_addr[INET_ADDRSTRLEN];
    char dst_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->ip_src, src_addr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->ip_dst, dst_addr, INET_ADDRSTRLEN);
    packet->src_addr.assign(src_addr);
    packet->dst_addr.assign(dst_addr);

    if (ip_len > len || ip_len < ip_header_len) {
        std::cerr << "received truncated IP datagram." << std::endl;
        return false;
    }
    size_t ip_payload_len = ip_len - ip_header_len;
    content += ip_header_len;
    process_tcp(packet, content, ip_payload_len);
    return true;
}

#define    ETHER_ADDR_LEN      6
#define    ETHERTYPE_IP        0x0800    /* IP protocol */

struct ether_header {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

static bool process_ethernet(struct packet_info *packet, const u_char *content, size_t len) {
    size_t ether_header_len = sizeof(struct ether_header);
    if (len < ether_header_len) {
        std::cerr << "received truncated Ether datagram." << std::endl;
        return false;
    }
    auto ethernet = reinterpret_cast<const struct ether_header *>(content);
    u_int16_t type = ntohs(ethernet->ether_type);
    if (type != ETHERTYPE_IP) {
        return false;
    }
    content += ether_header_len;
    process_ipv4(packet, content, len - ether_header_len);
    return true;
}

static void save_http_request(const custom_parser *parser, const capture_config *conf, const std::string &join_addr) {
    /*
    std::string path = conf->output_path + "/" + parser->get_host();
    int mk_ret = mkdir(path.c_str(), S_IRWXU);
    if (mk_ret != 0 && errno != EEXIST) {
        std::cerr << "mkdir [" << path << "] failed. ret=" << mk_ret << std::endl;
        exit(1);
    }
    std::string save_filename = path + "/" + urlencode(parser->get_url());
    */
    if (!conf->output_path.empty()) {
        std::string save_filename = conf->output_path + "/" + parser->get_host();
        std::ofstream out(save_filename, std::ios::app | std::ios::out);
        if (out.is_open()) {
            out << *parser << std::endl;
            out.close();
        } else {
            std::cerr << "ofstream [" << save_filename << "] is not opened." << std::endl;
            out.close();
            exit(1);
        }
    } else {
        std::cout << *parser << std::endl;
    }
}

custom_parser::custom_parser() {
    request_complete_flag = false;
    response_complete_flag = false;
    gzip_flag = false;
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

bool custom_parser::parse(const std::string &body, enum http_parser_type type) {
    if (parser.type != type) {
        http_parser_init(&parser, type);
    }
    if (parser.type == HTTP_REQUEST) {
        request.append(body);
    } else {
        response.append(body);
    }
    size_t parse_bytes = http_parser_execute(&parser, &settings, body.c_str(), body.size());
    return parse_bytes > 0 && HTTP_PARSER_ERRNO(&parser) == HPE_OK;
}

std::string custom_parser::get_response_body() const {
    return response_body;
}

void custom_parser::set_addr(const std::string &src_addr, const std::string &dst_addr) {
    this->request_address = src_addr;
    this->response_address = dst_addr;
}

int custom_parser::on_url(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    self->url.assign(at, length);
    self->method.assign(http_method_str(static_cast<enum http_method>(parser->method)));
    return 0;
};

int custom_parser::on_header_field(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    self->temp_header_field.assign(at, length);
    for (size_t i = 0; i < length; ++i) {
        if (at[i] >= 'A' && at[i] <= 'Z') {
            self->temp_header_field[i] = at[i] ^ (char) 0x20;
        }
    }
    return 0;
}

int custom_parser::on_header_value(http_parser *parser, const char *at, size_t length) {
    auto self = reinterpret_cast<custom_parser *>(parser->data);
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

int custom_parser::on_headers_complete(http_parser *parser) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    if (parser->type == HTTP_REQUEST) {
        self->request_header = self->request.substr(0, parser->nread);
    } else if (parser->type == HTTP_RESPONSE) {
        self->response_header = self->response.substr(0, parser->nread);
    }
    return 0;
}

int custom_parser::on_body(http_parser *parser, const char *at, size_t length) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    // std::cout << __func__ << " " << self->url << std::endl;
    if (parser->type == HTTP_REQUEST) {
        self->request_body.append(at, length);
    } else if (parser->type == HTTP_RESPONSE) {
        self->response_body.append(at, length);
    }
    return 0;
}

int custom_parser::on_message_complete(http_parser *parser) {
    custom_parser *self = reinterpret_cast<custom_parser *>(parser->data);
    if (parser->type == HTTP_REQUEST) {
        self->request_complete_flag = true;
    } else if (parser->type == HTTP_RESPONSE) {
        self->response_complete_flag = true;
        std::cout << ANSI_COLOR_CYAN << self->request_address << "->" << self->response_address << " " << self->host << " " << self->url << ANSI_COLOR_RESET << std::endl;
    }
    if (self->gzip_flag) {
        std::string new_body;
        if (gzip_decompress(self->response_body, new_body)) {
            self->response_body = std::move(new_body);
        } else {
            std::cerr << ANSI_COLOR_RED "uncompress error" ANSI_COLOR_RESET << std::endl;
        }
    }
    return 0;
}

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {

    // Data: |       Mac         |        Ip          |           TCP                  |
    // Len : |   ETHER_HDR_LEN   |   ip_header->ip_hl << 2   | tcp_header->th_off << 2 + sizeof body |

    auto conf = reinterpret_cast<capture_config *>(arg);

    struct packet_info packet;
    bool ret = process_ethernet(&packet, content, header->caplen);
    if (!ret || packet.body.empty()) {
        return;
    }

    std::string join_addr;
    get_join_addr(packet.src_addr, packet.dst_addr, join_addr);

    auto iter = http_requests.find(join_addr);
    if (iter == http_requests.end() || iter->second.empty()) {
        if (!packet.body.empty()) {
            auto parser = new custom_parser;
            if (parser->parse(packet.body, HTTP_REQUEST)) {
                parser->set_addr(packet.src_addr, packet.dst_addr);
                std::list<custom_parser *> requests;
                requests.push_back(parser);
                http_requests.emplace(std::make_pair(join_addr, requests));
            } else {
                delete parser;
            }
        }
    } else {
        std::list<custom_parser *> &parser_list = iter->second;
        for (auto parser : parser_list) {
        }
        auto last_parser = *(parser_list.rbegin());

        if (!packet.body.empty()) {
            if (last_parser->is_request_address(packet.src_addr)) {
                // Request
                if (last_parser->is_request_complete()) {
                    auto parser = new custom_parser;
                    if (parser->parse(packet.body, HTTP_REQUEST)) {
                        parser->set_addr(packet.src_addr, packet.dst_addr);
                        parser_list.push_back(parser);
                    }
                } else {
                    last_parser->parse(packet.body, HTTP_REQUEST);
                }
            } else {
                for (auto it = parser_list.begin(); it != parser_list.end(); ++it) {
                    if (!(*it)->is_response_complete()) {
                        (*it)->parse(packet.body, HTTP_RESPONSE);
                        break;
                    } else {
                        std::cerr << ANSI_COLOR_RED "get response exception, body [" << packet.body
                                  << "]" ANSI_COLOR_RESET << std::endl;
                    }
                }
            }
        }

        for (auto it = parser_list.begin(); it != parser_list.end();) {
            if ((*it)->is_response_complete()) {
                save_http_request((*it), conf, join_addr);
                delete (*it);
                it = iter->second.erase(it);
            } else {
                ++it;
            }
        }

        if (iter->second.empty()) {
            http_requests.erase(iter);
        }
    }
}

static const struct option longopts[] = {
        {"help",            no_argument,       NULL, 'h'},
        {"interface",       required_argument, NULL, 'i'},
        {"filter",          required_argument, NULL, 'f'},
        {"snapshot-length", required_argument, NULL, 's'},
        {"port",            required_argument, NULL, 'p'},
        {"output-path",     required_argument, NULL, 'w'},
        {"output-pipe",     no_argument,       NULL, 'x'},
        {NULL, 0,                              NULL, 0}
};

#define SHORTOPTS "hi:f:s:p:w:x"

extern char pcap_version[];

int print_usage() {
    std::cerr << "libpcap version" << pcap_version << "\n"
              << "httpdump v0.1\n"
              << "\n"
              << "Usage: http_dump [-i interface] [-f filter] [-s snapshot-length] [-p port] [-w output-path]"
              << "\n";
    exit(1);
}

extern char *optarg;            /* getopt(3) external variables */
extern int optind, opterr, optopt;

void print_pipeline() {
    std::string cin_line;
    while (std::getline(std::cin, cin_line)) {
        std::cout << cin_line << std::endl;
    }
    exit(0);
}

capture_config *default_config() {
    auto conf = new capture_config;

    conf->snaplen = MAXIMUM_SNAPLEN;
    conf->port = 0;
    conf->device[0] = 0;
    conf->filter = "tcp";

    return conf;
}

int init_capture_config(int argc, char **argv, capture_config *conf, char *errbuf) {

    // pcap_if_t *devices = NULL, *iter = NULL;
    const char *default_device = NULL;
    int cnt, op, i;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 'i':
                std::strncpy(conf->device, optarg, sizeof(conf->device));
                break;
            case 'f':
                conf->filter = optarg;
                break;
            case 's':
                conf->snaplen = atoi(optarg);
                if (conf->snaplen == 0) {
                    conf->snaplen = MAXIMUM_SNAPLEN;
                }
                break;
            case 'p':
                conf->port = atoi(optarg);
                break;
            case 'h':
                print_usage();
                break;
            case 'w':
                conf->output_path = optarg;
                break;
            case 'x':
                print_pipeline();
                break;
            default:
                exit(1);
                break;
        }
    }

    if (conf->device[0] == 0) {
        default_device = pcap_lookupdev(errbuf);
        if (default_device) {
            std::strncpy(conf->device, default_device, sizeof(conf->device));
        }
    }

    if (!conf->output_path.empty()) {
        int mk_ret = mkdir(conf->output_path.c_str(), S_IRWXU);
        if (mk_ret != 0 && errno != EEXIST) {
            std::cerr << "mkdir [" << conf->output_path << "] failed. ret=" << mk_ret << std::endl;
            exit(1);
        }
    }

    std::cout << "interface: " << conf->device << std::endl;
    std::cout << "snapshot-length: " << conf->snaplen << std::endl;
    std::cout << "port: " << conf->port << std::endl;
    std::cout << "output_path: " << conf->output_path << std::endl;
    std::cout << "filter: " << conf->filter << std::endl;

    return 0;
}

int main(int argc, char **argv) {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program fcode;

    auto cap_conf = default_config();
    if (-1 == init_capture_config(argc, argv, cap_conf, errbuf)) {
        return 1;
    }

    if (-1 == pcap_lookupnet(cap_conf->device, &net, &mask, errbuf)) {
        std::cerr << "pcap_lookupnet(): " << errbuf << std::endl;
        return 1;
    }

    // 混杂模式, 不超时
    handle = pcap_open_live(cap_conf->device, cap_conf->snaplen, 1, 1, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live(): " << errbuf << std::endl;
        return 1;
    }

    if (-1 == pcap_compile(handle, &fcode, cap_conf->filter.c_str(), 1, mask)) {
        std::cerr << "pcap_compile(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    if (-1 == pcap_setfilter(handle, &fcode)) {
        std::cerr << "pcap_setfilter(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_freecode(&fcode);

    if (-1 == pcap_loop(handle, -1, pcap_callback, reinterpret_cast<u_char *>(cap_conf))) {
        std::cerr << "pcap_loop(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}
