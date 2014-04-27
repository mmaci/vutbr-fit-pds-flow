
#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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


inline bool operator< (const in6_addr& lhs, const in6_addr& rhs)
{
    for (uint8_t i = 0; i < 16; ++i) {
        if (lhs.s6_addr[i] < rhs.s6_addr[i])
            return true;
    }
    return false;
}


void printFlow(struct flow* fl) {
    char srcip[INET6_ADDRSTRLEN];
    char dstip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(fl->src_addr), srcip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(fl->dst_addr), dstip, INET6_ADDRSTRLEN);
    fprintf(stdout, "%s:%d -> %s:%d, pkts: %" PRIi64" , bytes: %" PRIi64" \n", srcip, ntohs(fl->src_port), dstip, ntohs(fl->dst_port),
            __builtin_bswap64(fl->packets),
            __builtin_bswap64(fl->bytes));
}

template<typename T>
void printFlow(std::multimap<T, flow> data) {
    for (typename std::multimap<T, flow>::iterator ii = data.begin(); ii != data.end(); ++ii) {
        printFlow(&ii->second);
    }
}

in6_addr getMask(in6_addr const& address, uint8_t mask) {
    in6_addr maskedIp;

    return maskedIp;
}

std::vector<std::string> split(std::string const& in, char delimiter = ' ') {
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

    uint8_t aggr, sort, mask = 0;
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
                                    mask = atoi(tokens[1].c_str());
                                    if (mask > 1 && mask <= 128)
                                        break;
                                } else if (aggr == SRC_IPV4 || aggr == DST_IPV4) {
                                    mask = atoi(tokens[1].c_str());
                                    if (mask > 1 && mask <= 32)
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
                uint8_t sort;
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

    std::ifstream f(filename, std::ifstream::in | std::ifstream::binary);
    if (!f) {
        std::cerr << "Unable to open file (filename: " << filename << ")." << std::endl;
        return EXIT_FAILURE;
    }
    
    switch (aggr) {
        case SRC_IP:
        {
            std::multimap<in6_addr, flow> data;
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                data.insert(std::make_pair(fl.src_addr, fl));
            }            
            printFlow(data);
            break;
        }
        case SRC_IPV4:
        case SRC_IPV6:
        {
            std::multimap<in6_addr, flow> data;
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                data.insert(std::make_pair(getMask(fl.src_addr, mask), fl));
            }            
            printFlow(data);
            break;
        }
        case DST_IP:
        {
            std::multimap<in6_addr, flow> data;
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                data.insert(std::make_pair(fl.dst_addr, fl));
            }            
            printFlow(data);
            break;
        }
        case DST_IPV4:            
        case DST_IPV6:
        {
            std::multimap<in6_addr, flow> data;
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                data.insert(std::make_pair(getMask(fl.dst_addr, mask), fl));
            }            
            printFlow(data);
            break;
        }
        case SRC_PORT:
        {            
            std::multimap<uint16_t, flow> data;
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                data.insert(std::make_pair(fl.src_port, fl));
            }            
            printFlow(data);
            break;
        }
        case DST_PORT:
        {            
            std::multimap<uint16_t, flow> data;
            while (f.good()) {
                flow fl;
                f.read(reinterpret_cast<char*> (&fl), sizeof (flow));
                data.insert(std::make_pair(fl.dst_port, fl));
            }            
            printFlow(data);
            break;
        }
    }

    f.close();

    return (EXIT_SUCCESS);
}
