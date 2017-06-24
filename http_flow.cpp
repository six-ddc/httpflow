#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string>
#include <sstream>
#include <list>
#include <map>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex>
#include "util.h"
#include "custom_parser.h"
#include "data_link.h"

#define HTTPFLOW_VERSION "0.0.5"

#define MAXIMUM_SNAPLEN 262144

struct capture_config {
#define IFNAMSIZ    16
    int snaplen;
    std::string output_path;
    char device[IFNAMSIZ];
    std::string file_name;
    std::string filter;
    std::regex* url_filter;
    int datalink_size;
};

std::map<std::string, std::list<custom_parser *> > http_requests;

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
    const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(content);

    size_t tcp_header_len = TH_OFF(tcp_header) << 2;
    if (len < tcp_header_len) {
        std::cerr << "received truncated TCP datagram." << std::endl;
        return false;
    }

    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);

    char buff[128];
    std::snprintf(buff, 128, "%s:%d", packet->src_addr.c_str(), src_port);
    packet->src_addr.assign(buff);
    std::snprintf(buff, 128, "%s:%d", packet->dst_addr.c_str(), dst_port);
    packet->dst_addr.assign(buff);
    packet->is_fin = !!(tcp_header->th_flags & (TH_FIN | TH_RST));

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
    const struct ip *ip_header = reinterpret_cast<const struct ip *>(content);
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
    return process_tcp(packet, content, ip_payload_len);
}

#define    ETHER_ADDR_LEN      6
#define    ETHERTYPE_IP        0x0800    /* IP protocol */

struct ether_header {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

void process_packet(const std::regex *url_filter, const std::string &output_path, const u_char* data, size_t len) {

    struct packet_info packet;
    bool ret = process_ipv4(&packet, data, len);
    if ((!ret || packet.body.empty()) && !packet.is_fin) {
        return;
    }

    std::string join_addr;
    get_join_addr(packet.src_addr, packet.dst_addr, join_addr);

    std::map<std::string, std::list<custom_parser *> >::iterator iter = http_requests.find(join_addr);
    if (iter == http_requests.end() || iter->second.empty()) {
        if (!packet.body.empty()) {
            custom_parser *parser = new custom_parser;
            if (parser->parse(packet.body, HTTP_REQUEST)) {
                parser->set_addr(packet.src_addr, packet.dst_addr);
                std::list<custom_parser *> requests;
                requests.push_back(parser);
                http_requests.insert(std::make_pair(join_addr, requests));
            } else {
                delete parser;
            }
        }
    } else {
        std::list<custom_parser *> &parser_list = iter->second;
        custom_parser *last_parser = *(parser_list.rbegin());

        if (!packet.body.empty()) {
            if (last_parser->is_request_address(packet.src_addr)) {
                // Request
                if (last_parser->is_request_complete()) {
                    custom_parser* parser = new custom_parser;
                    if (parser->parse(packet.body, HTTP_REQUEST)) {
                        parser->set_addr(packet.src_addr, packet.dst_addr);
                        parser_list.push_back(parser);
                    } else {
                        delete parser;
                    }
                } else {
                    last_parser->parse(packet.body, HTTP_REQUEST);
                }
            } else {
                for (std::list<custom_parser *>::iterator it = parser_list.begin(); it != parser_list.end(); ++it) {
                    if (!(*it)->is_response_complete()) {
                        (*it)->parse(packet.body, HTTP_RESPONSE);
                        break;
                    } else {
                        std::cerr << ANSI_COLOR_RED << "get response exception, body [" << packet.body
                                  << "]" << ANSI_COLOR_RESET << std::endl;
                    }
                }
            }
        }

        for (std::list<custom_parser *>::iterator it = parser_list.begin(); it != parser_list.end();) {
            if ((*it)->is_response_complete() || packet.is_fin) {
                (*it)->save_http_request(url_filter, output_path, join_addr);
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

void pcap_callback(u_char *arg, const struct pcap_pkthdr *header, const u_char *content) {

    // Data: |       Mac         |        Ip          |           TCP                  |
    // Len : |   ETHER_HDR_LEN   |   ip_header->ip_hl << 2   | tcp_header->th_off << 2 + sizeof body |

    capture_config *conf = reinterpret_cast<capture_config *>(arg);

    // skip datalink
    content += conf->datalink_size;
    size_t len = header->caplen - conf->datalink_size;

    return process_packet(conf->url_filter, conf->output_path, content, len);
}

static const struct option longopts[] = {
        {"help",            no_argument,       NULL, 'h'},
        {"interface",       required_argument, NULL, 'i'},
        {"filter",          required_argument, NULL, 'f'},
        {"url_filter",      required_argument, NULL, 'u'},
        {"pcap-file",       required_argument, NULL, 'r'},
        {"snapshot-length", required_argument, NULL, 's'},
        {"output-path",     required_argument, NULL, 'w'},
        {NULL, 0,                              NULL, 0}
};

#define SHORTOPTS "hi:f:u:r:w:"

int print_usage() {
    std::cerr << "libpcap version " << pcap_lib_version() << "\n"
              << "httpflow version " HTTPFLOW_VERSION "\n"
              << "\n"
              << "Usage: httpflow [-i interface | -r pcap-file] [-f packet-filter] [-u url-filter] [-w output-path]" << "\n"
              << "\n"
              << "  -i interface      Listen on interface" << "\n"
              << "  -r pcap-file      Read packets from file (which was created by tcpdump with the -w option)" << "\n"
              << "                    Standard input is used if file is '-'" << "\n"
              << "  -f packet-filter  Selects which packets will be dumped" << "\n"
              << "                    If filter expression is given, only packets for which expression is 'true' will be dumped" << "\n"
              << "                    For the expression syntax, see pcap-filter(7)" << "\n"
              << "  -u url-filter     Matches which urls will be dumped" << "\n"
              << "  -w output-path    Write the http request and response to a specific directory" << "\n"
              << "\n"
              << "  For more information, see https://github.com/six-ddc/httpflow" << "\n\n";
    exit(0);
}

extern char *optarg;            /* getopt(3) external variables */
extern int optind, opterr, optopt;

capture_config *default_config() {
    capture_config *conf = new capture_config;

    conf->snaplen = MAXIMUM_SNAPLEN;
    conf->device[0] = 0;
    conf->filter = "tcp";

    return conf;
}

int init_capture_config(int argc, char **argv, capture_config *conf, char *errbuf) {

    // pcap_if_t *devices = NULL, *iter = NULL;
    const char *default_device = NULL;
    int cnt, op, i;
    std::string url_regex;

    while ((op = getopt_long(argc, argv, SHORTOPTS, longopts, NULL)) != -1) {
        switch (op) {
            case 'i':
                std::strncpy(conf->device, optarg, sizeof(conf->device));
                break;
            case 'f':
                conf->filter = optarg;
                break;
            case 'u':
                try {
                    url_regex.assign(optarg);
                    conf->url_filter = new std::regex(url_regex);
                } catch (const std::regex_error& e) {
                    std::cerr << "invalid regular expression (" << url_regex << "): " << e.what() << std::endl;
                    exit(1);
                }

                break;
            case 'r':
                conf->file_name = optarg;
                break;
            case 'h':
                print_usage();
                break;
            case 'w':
                conf->output_path = optarg;
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

    if (conf->file_name.empty()) {
        std::cerr << "interface: " << conf->device << std::endl;
    } else {
        if (conf->file_name == "-") {
            std::cerr << "pcap-file: [stdin]" << std::endl;
        } else {
            std::cerr << "pcap-file: " << conf->file_name << std::endl;
        }
    }
    if (!conf->output_path.empty()) {
        std::cerr << "output_path: " << conf->output_path << std::endl;
    }
    std::cerr << "filter: " << conf->filter << std::endl;
    if (!url_regex.empty()) {
        std::cerr << "url_filter: " << url_regex << std::endl;
    }

    return 0;
}

int main(int argc, char **argv) {

    is_atty = isatty(fileno(stdout));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    bpf_u_int32 net, mask;
    struct bpf_program fcode;
    int datalink_id;
    std::string datalink_str;

    capture_config *cap_conf = default_config();
    if (-1 == init_capture_config(argc, argv, cap_conf, errbuf)) {
        return 1;
    }

    if (!cap_conf->file_name.empty()) {
        handle = pcap_open_offline(cap_conf->file_name.c_str(), errbuf);
        if (!handle) {
            std::cerr << "pcap_open_offline(): " << errbuf << std::endl;
            return 1;
        }
    } else {
        if (-1 == pcap_lookupnet(cap_conf->device, &net, &mask, errbuf)) {
            std::cerr << "pcap_lookupnet(): " << errbuf << std::endl;
            return 1;
        }

        handle = pcap_open_live(cap_conf->device, cap_conf->snaplen, 0, 1000, errbuf);
        if (!handle) {
            std::cerr << "pcap_open_live(): " << errbuf << std::endl;
            return 1;
        }

        pcap_datalink(handle);
    }

    if (-1 == pcap_compile(handle, &fcode, cap_conf->filter.c_str(), 0, mask)) {
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

	datalink_id = pcap_datalink(handle);
	datalink_str = datalink2str(datalink_id);
	cap_conf->datalink_size = datalink2off(datalink_id);
    std::cerr << "datalink: " << datalink_id << "(" << datalink_str << ") header size: " << cap_conf->datalink_size << std::endl;

    if (-1 == pcap_loop(handle, -1, pcap_callback, reinterpret_cast<u_char *>(cap_conf))) {
        std::cerr << "pcap_loop(): " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    delete cap_conf;

    pcap_close(handle);
    return 0;
}
