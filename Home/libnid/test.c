#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nids.h>
#define Max_Packets 10

int packetcount=0;

void process_packet(struct ip *ip_header) {
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    switch (ip_header->ip_p) {
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        case 28:
            printf("Protocol: ARP\n");
            break;
        default:
            printf("Protocol: Unknown\n");
            break;
    }

    packetcount++;
    printf("\n");
    if (packetcount >= Max_Packets) {
        nids_exit;
    }
}

void packet_callback(struct ip *ip_header) {
    process_packet(ip_header);
}

int main() {
    if (!nids_init()) {
        fprintf(stderr, "Error initializing libnids.\n");
        exit(1);
    }

    // 规则
    nids_params.pcap_filter = "ip or udp or icmp or arp";

    nids_register_ip(packet_callback);

    nids_run();
    
    printf("Capture %d packets\n",packetcount);
    return 0;
}