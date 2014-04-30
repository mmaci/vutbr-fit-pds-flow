
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>
#include <dirent.h>

#include "constants.h"


const std::string AGGR_ARGS[] = {
    "srcip", // SRC_IP
    "srcip4", // SRC_IPV4
    "srcip6", // SRC_IPV6
    "dstip", // DST_IP
    "dstip4", // DST_IPV4
    "dstip6", // DST_IPV6
    "srcport", // SRC_PORT
    "dstport" // DST_PORT
};

enum Aggr {
    SRC_IP = 0,
    SRC_IPV4,
    SRC_IPV6,
    DST_IP,
    DST_IPV4,
    DST_IPV6,
    SRC_PORT,
    DST_PORT,

    MAX_AGGR
};

const std::string SORT_ARGS[] = {
    "packets", // PACKETS
    "bytes" // BYTES
};

enum Sort {
    PACKETS = 0,
    BYTES,

    MAX_SORT
};

enum IPType {
    IP_V4,
    IP_V6
};

// needed to use multimap with in6_addr&

inline bool operator<(const in6_addr& lhs, const in6_addr& rhs) {
    for (uint8_t i = 0; i < 16; ++i) {
        if (lhs.s6_addr[i] < rhs.s6_addr[i])
            return true;
    }
    return false;
}

void printFlow(struct flow* fl, FILE* pFile) {
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(fl->src_addr), srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(fl->dst_addr), dstip, INET6_ADDRSTRLEN);
    fprintf(pFile, "%s:%d -> %s:%d, pkts: %" PRIi64" , bytes: %" PRIi64" \n", srcip, ntohs(fl->src_port), dstip, ntohs(fl->dst_port),
            fl->packets,
            fl->bytes);
}

template<typename T>
void printFlow(std::map<T, flow> data, const char* filename) {
    FILE* pFile = fopen(filename, "w");
    for (typename std::map<T, flow>::iterator ii = data.begin(); ii != data.end(); ++ii) {
        printFlow(&ii->second, pFile);
    }
    fclose(pFile);
}

template<typename T>
void printFlow(std::multimap<T, flow> data, const char* filename) {
    FILE* pFile = fopen(filename, "w");
    for (typename std::multimap<T, flow>::reverse_iterator ii = data.rbegin(); ii != data.rend(); ++ii) {
        printFlow(&ii->second, pFile);
    }
    fclose(pFile);
}

in6_addr getMask(in6_addr const& address, uint8_t prefix, IPType const& ip) {
    in6_addr mask, maskedIp;

    memset(&maskedIp, 0, sizeof (struct in6_addr));
    memset(&mask, 0, sizeof (struct in6_addr));

    uint32_t tmpv4;
    uint64_t tmpv6[2];
    switch (ip) {
        case IP_V4:
            tmpv4 = ((uint32_t) (~0) << (32 - prefix));
            memcpy(&mask.s6_addr[12], &tmpv4, sizeof (uint32_t));

            for (uint8_t i = 12; i < 16; ++i)
                maskedIp.s6_addr[i] = address.s6_addr[i] & mask.s6_addr[i];

            break;
        case IP_V6:
            if (prefix <= 64) {
                tmpv6[0] = ((uint64_t) (~0) << (64 - prefix));
            } else {
                prefix -= 64;
                tmpv6[0] = (uint64_t) (~0);
                tmpv6[1] = ((uint64_t) (~0) << (64 - prefix));
            }
            memcpy(mask.s6_addr, tmpv6, sizeof (uint64_t));
            memcpy(&mask.s6_addr[8], &tmpv6[1], sizeof (uint64_t));

            for (uint8_t i = 0; i < 16; ++i)
                maskedIp.s6_addr[i] = address.s6_addr[i] & mask.s6_addr[i];

            break;
    }

    return maskedIp;
}

std::vector<std::string> split(std::string const& in, char const& delimiter = ' ') {
    std::stringstream ss(in);
    std::string out;
    std::vector<std::string> tokens;
    while (std::getline(ss, out, delimiter)) {
        tokens.push_back(out);
    }
    return tokens;
}

int compare(std::string const& a, std::string const& b) {
    int diff = a.compare(b);
    return diff == 0 ? a.size() - b.size() : diff;
}

int main(int argc, char *argv[]) {
    int opt;
    char *filename;
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << "[-f filename]" << std::endl;
        return (EXIT_FAILURE);
    }

    uint8_t aggr, sort, prefix = 0;
    while ((opt = getopt(argc, argv, "f:a:s:")) != -1) {
        std::string arg(optarg);

        switch (opt) {
                // filename
            case 'f':
                filename = optarg;
                break;

                // aggregation type
            case 'a':
                for (aggr = SRC_IP; aggr < MAX_AGGR; ++aggr) {
                    if (arg.compare(AGGR_ARGS[aggr]) == 0) {
                        if (aggr == SRC_IPV4 || aggr == SRC_IPV6 || aggr == DST_IPV4 || aggr == DST_IPV6) {
                            std::vector<std::string> tokens = split(arg, '/');
                            if (tokens[0].size() == AGGR_ARGS[aggr].size() && tokens.size() == 2) {
                                if (aggr == SRC_IPV6 || aggr == DST_IPV6) {
                                    prefix = atoi(tokens[1].c_str());
                                    if (prefix > 1 && prefix <= 128)
                                        break;
                                } else if (aggr == SRC_IPV4 || aggr == DST_IPV4) {
                                    prefix = atoi(tokens[1].c_str());
                                    if (prefix > 1 && prefix <= 32)
                                        break;
                                }
                            }
                        } else {
                            if (arg.size() == AGGR_ARGS[aggr].size())
                                break;
                        }
                    }
                }

                if (aggr == MAX_AGGR) {
                    std::cerr << "Usage: " << argv[0] << "[-f filename]" << std::endl;
                    return (EXIT_FAILURE);
                }
                break;

                // sort type    
            case 's':
                for (sort = PACKETS; sort < MAX_SORT; ++sort) {
                    if (compare(arg, SORT_ARGS[sort]) == 0)
                        break;
                }

                if (sort == MAX_SORT) {
                    std::cerr << "Usage: " << argv[0] << "[-f filename]" << std::endl;
                    return (EXIT_FAILURE);
                }
                break;

                // other options    
            default:
                std::cerr << "Usage: " << argv[0] << "[-f filename]" << std::endl;
                return (EXIT_FAILURE);
        }
    }

    // reading file

    DIR* dir = opendir(filename);
    if (dir != NULL) {        
        struct dirent* dp;
        while ((dp = readdir(dir)) != NULL) {
            std::string fn(dp->d_name);
            std::string type(".bin");
            size_t pos = fn.find(type);
            if (pos != std::string::npos && pos + type.length() == fn.length()) { // also check if ext is really at the end
                std::cout << dp->d_name << std::endl;
            }            
        }
    }
    closedir(dir);     

    std::ifstream f(filename, std::ifstream::in | std::ifstream::binary);
    if (!f) {
        std::cerr << "Unable to open file (filename: " << filename << ")." << std::endl;
        return EXIT_FAILURE;
    }

    std::map<in6_addr, flow> ipdata;
    std::map<uint16_t, flow> portdata;
    switch (aggr) {
        case SRC_IP:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<in6_addr, flow>::iterator, bool> el = ipdata.insert(std::make_pair(fl.src_addr, fl));
                if (!el.second) { // element already existed
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case SRC_IPV4:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<in6_addr, flow>::iterator, bool> el = ipdata.insert(std::make_pair(getMask(fl.src_addr, prefix, IP_V4), fl));
                if (!el.second) { // element already existed
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case SRC_IPV6:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<in6_addr, flow>::iterator, bool> el = ipdata.insert(std::make_pair(getMask(fl.src_addr, prefix, IP_V6), fl));
                if (!el.second) { // element already existed
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case DST_IP:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<in6_addr, flow>::iterator, bool> el = ipdata.insert(std::make_pair(fl.dst_addr, fl));
                if (!el.second) { // element already existed
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case DST_IPV4:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<in6_addr, flow>::iterator, bool> el = ipdata.insert(std::make_pair(getMask(fl.dst_addr, prefix, IP_V4), fl));
                if (!el.second) {
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case DST_IPV6:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<in6_addr, flow>::iterator, bool> el = ipdata.insert(std::make_pair(getMask(fl.dst_addr, prefix, IP_V6), fl));
                if (!el.second) {
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case SRC_PORT:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<uint16_t, flow>::iterator, bool> el = portdata.insert(std::make_pair(fl.src_port, fl));
                if (!el.second) {
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
        case DST_PORT:
        {
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                fl.bytes = __builtin_bswap64(fl.bytes);
                fl.packets = __builtin_bswap64(fl.packets);

                std::pair < std::map<uint16_t, flow>::iterator, bool> el = portdata.insert(std::make_pair(fl.dst_port, fl));
                if (!el.second) {
                    el.first->second.packets += fl.packets;
                    el.first->second.bytes += fl.bytes;
                }
            }
            break;
        }
    }
    std::multimap<uint64_t, flow> sorted;
    switch (aggr) {
        case SRC_IP:
        case SRC_IPV4:
        case SRC_IPV6:
        case DST_IP:
        case DST_IPV4:
        case DST_IPV6:
            switch (sort) {
                case PACKETS:
                    for (std::map<in6_addr, flow>::const_iterator ii = ipdata.begin(); ii != ipdata.end(); ++ii)
                        sorted.insert(std::make_pair(ii->second.packets, ii->second));

                    break;
                case BYTES:
                    for (std::map<in6_addr, flow>::const_iterator ii = ipdata.begin(); ii != ipdata.end(); ++ii)
                        sorted.insert(std::make_pair(ii->second.bytes, ii->second));

                    break;
            }
            break;
        case SRC_PORT:
        case DST_PORT:
            switch (sort) {
                case PACKETS:
                    for (std::map<uint16_t, flow>::const_iterator ii = portdata.begin(); ii != portdata.end(); ++ii)
                        sorted.insert(std::make_pair(ii->second.packets, ii->second));

                    break;
                case BYTES:
                    for (std::map<uint16_t, flow>::const_iterator ii = portdata.begin(); ii != portdata.end(); ++ii)
                        sorted.insert(std::make_pair(ii->second.bytes, ii->second));

                    break;
            }

            break;
    }
    printFlow(sorted, "sorted.txt");


    f.close();

    return (EXIT_SUCCESS);
}
