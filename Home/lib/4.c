#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAX_LINE_LENGTH 100

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    pcap_dump(arg, pkthdr, packet);
    printf("Received Packet Size: %d\n", pkthdr->len);
    return;
}

int main() {
    FILE *fp;
    char errBuf[PCAP_ERRBUF_SIZE];
    char line[MAX_LINE_LENGTH];
    char config_path[] = "config.txt";
    char * devStr[MAX_LINE_LENGTH];
    char path[MAX_LINE_LENGTH];
    char condition[MAX_LINE_LENGTH];
    char rule[MAX_LINE_LENGTH];
    pcap_t *packet;
    struct pcap_pkthdr packet_header;
    struct ether_header *ethernet_header;

    fp = fopen(config_path, "r");

    if (fp == NULL) {
        fprintf(stderr, "Error opening file: %s\n", config_path);
        exit(EXIT_FAILURE);
    }

    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        // get the first string variable
        if (strstr(line, "devStr=") != NULL) {
            sscanf(line, "devStr=%s", devStr);
        }
        if(strstr(line,"path=")!=NULL){
            sscanf(line,"path=%s",path);
        }
        if (strstr(line,"condition=")!=NULL){
            sscanf(line,"condition=%s",condition);
        }
        if(strstr(line,"rule=")!=NULL){
            sscanf(line,"rule=%s",rule);
        }
    }

    fclose(fp);
    struct bpf_program fb;
    bpf_u_int32 net, mask;
    pcap_t * device; 
    if(strcmp(condition,"live")==0){
    device=pcap_open_live(devStr, 65535, 1, 0, errBuf);
    }
    else {
    printf("You are offline!\n");
    device=pcap_open_offline(path,errBuf);
    }
    pcap_dumper_t* out_pcap;
    out_pcap  = pcap_dump_open(device,path);
    if (pcap_compile(device, &fb, rule, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", rule, pcap_geterr(device));
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(device, &fb) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", rule, pcap_geterr(device));
        return EXIT_FAILURE;
    }

   if (device == NULL) {
        printf("Error opening device: %s\n", errBuf);
        exit(1);
    }

    while (1) {
        packet = pcap_next(device, &packet_header);
        if (packet == NULL) {
            printf("Error capturing packet\n");
            continue;
        }
        ethernet_header = (struct ether_header*) packet;
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_ip_header(packet);
        } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_arp_header(packet);
        } else {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            printf("Unknown packet type\n");
        }
    }

    pcap_close(packet);
    return 0;
}

void print_ethernet_header(const u_char *packet) {
    struct ether_header *ethernet_header;
    ethernet_header = (struct ether_header*) packet;

    printf("Ethernet header:\n");
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_shost[0], ethernet_header->ether_shost[1],
           ethernet_header->ether_shost[2], ethernet_header->ether_shost[3],
           ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1],
           ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3],
           ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);
    printf("\tType: %d\n", ntohs(ethernet_header->ether_type));
}

void print_ip_header(const u_char *packet) {
    struct iphdr *ip_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));

    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);

    printf("IP header:\n");
    printf("\tSource IP: %s\n", source_ip);
    printf("\tDestination IP: %s\n", dest_ip);
    printf("\tProtocol: %d\n", ip_header->protocol);
}

void print_arp_header(const u_char *packet) {
    struct ether_arp *arp_header;
    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    arp_header = (struct ether_arp*)(packet + sizeof(struct ether_header));

    inet_ntop(AF_INET, arp_header->arp_spa, source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, arp_header->arp_tpa, dest_ip, INET_ADDRSTRLEN);

    printf("ARP header:\n");
    printf("\tSource IP: %s\n", source_ip);
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->arp_sha[0], arp_header->arp_sha[1], arp_header->arp_sha[2],
           arp_header->arp_sha[3], arp_header->arp_sha[4], arp_header->arp_sha[5]);
    printf("\tDestination IP: %s\n", dest_ip);
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           arp_header->arp_tha[0], arp_header->arp_tha[1], arp_header->arp_tha[2],
           arp_header->arp_tha[3], arp_header->arp_tha[4], arp_header->arp_tha[5]);
} 