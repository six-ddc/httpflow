#include "util.h"

bool is_atty = true;

bool is_plain_text(const std::string &s) {
    // The algorithm works by dividing the set of bytecodes [0..255] into three
    // categories:
    // 	- The white list of textual bytecodes:
    //  	9 (TAB), 10 (LF), 13 (CR), 32 (SPACE) to 255.
    // 	- The gray list of tolerated bytecodes:
    //  	7 (BEL), 8 (BS), 11 (VT), 12 (FF), 26 (SUB), 27 (ESC).
    // 	- The black list of undesired, non-textual bytecodes:
    //  	0 (NUL) to 6, 14 to 31.
    // If a file contains at least one byte that belongs to the white list and
    // no byte that belongs to the black list, then the file is categorized as
    // plain text; otherwise, it is categorized as binary.  (The boundary case,
    // when the file is empty, automatically falls into the latter category.)
    if (s.empty()) {
        return true;
    }
    size_t white_list_char_count = 0;
    for (int i = 0; i < s.size(); ++i) {
        const unsigned char c = s[i];
        if (c == 9 || c == 10 || c == 13 || (c >= 32 && c <= 255)) {
            // white list
            white_list_char_count++;
        } else if ((c <= 6) || (c >= 14 && c <= 31)) {
            // black list
            return 0;
        }
    }
    return white_list_char_count >= 1 ? true : false;
}

void get_join_addr(const std::string &src_addr, const std::string &dst_addr, std::string &ret) {
    if (src_addr < dst_addr) {
        ret = src_addr + "-" + dst_addr;
    } else {
        ret = dst_addr + "-" + src_addr;
    }
}

std::string timeval2tr(const struct timeval *ts) {
    struct tm *local_tm = localtime(&ts->tv_sec);
    std::string time_str;
    time_str.resize(15);
    sprintf(&time_str[0], "%02d:%02d:%02d.%06d", local_tm->tm_hour, local_tm->tm_min,
            local_tm->tm_sec, (int) ts->tv_usec);
    return time_str;
}

#define GZIP_CHUNK 16384

bool gzip_decompress(std::string &src, std::string &dst) {
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

std::string urlencode(const std::string &s) {
    static const char lookup[] = "0123456789abcdef";
    std::stringstream e;
    for (int i = 0; i < s.size(); ++i) {
        const char c = s[i];
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
