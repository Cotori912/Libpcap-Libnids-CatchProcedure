#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <nids.h>
#include <string.h>

void ip_packet_handler(struct ip *ip_header, int len)
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    struct in_addr addr;

    addr.s_addr = ip_header->ip_src.s_addr;
    inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
    addr.s_addr = ip_header->ip_dst.s_addr;
    inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));

    printf("IP packet: %s -> %s\n", src_ip, dst_ip);
}

int main()
{
        FILE *fp;
        char line[MAX_LINE_LENGTH];
        char config_path[] = "config.txt";
        char string1[MAX_LINE_LENGTH];
        int condition;[MAX_LINE_LENGTH];
        char rule[MAX_LINE_LENGTH];
        fp = fopen(config_path, "r");
        if (fp == NULL) {
        fprintf(stderr, "Error opening file: %s\n", config_path);
        exit(EXIT_FAILURE);
        }

        while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        if (strstr(line, "device=") != NULL) {
            sscanf(line, "devStr=%s", string1);
        }
        if (strstr(line,"rule=")!=NULL){
            sscanf(line,"rule=%s",rule);
        }
        if (strstr(line,"condition=")!=NULL){
            sscanf(line,"condition=%s",condition);
        }
    }

    fclose(fp);
    nids_params.device = NULL; // Use default network device
    nids_params.pcap_filter = NULL; // No pcap filter
    nids_params.filename = NULL; // No offline pcap file
    nids_params.scan_num_hosts = 0; // Disable portscan detection

    if (!nids_init())
    {
        fprintf(stderr, "Error initializing libnids: %s\n", nids_errbuf);
        exit(1);
    }

    nids_register_ip(ip_packet_handler);
    nids_run();

    return 0;
}