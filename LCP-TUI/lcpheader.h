#ifndef __LCPHEADER_H__
#define __LCPHEADER_H__
#include <pcap.h>

void print_ethernet_header(const u_char *packet);

void print_ip_header(const u_char *packet);

void print_tcp_header(const u_char *packet);

void print_udp_header(const u_char *packet);

void print_arp_header(const u_char *packet);

void print_icmp_header(const u_char *packet);


#endif
