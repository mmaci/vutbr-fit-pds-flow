/* 
 * File:   constants.h
 * Author: Pavel
 *
 * Created on 13. duben 2014, 12:53
 */

#ifndef CONSTANTS_H
#define	CONSTANTS_H

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

struct flow {
    uint32_t sa_family;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t packets;
    uint64_t bytes;
}; 

#endif	/* CONSTANTS_H */

