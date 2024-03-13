#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nids.h>
 
void callback_ip(struct ip *ip_packet, int len)
{
    printf("IP packet received\n");
    // 进行IP数据包解析和处理
}
 
void callback_arp(struct arp_header *arp_packet, int len)
{
    printf("ARP packet received\n");
    // 进行ARP数据包解析和处理
}
 
int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(1);
    }
 
    char *dev = argv[1];
    if (nids_init() == -1) {
        printf("nids_init() failed\n");
        exit(1);
    }
 
    nids_params.device = dev;
    nids_register_ip(callback_ip);
    nids_register_arp(callback_arp);
    nids_run();
 
    return 0;
}