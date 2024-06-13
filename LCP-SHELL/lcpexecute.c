#include "lcpexecute.h"
#include "lcpfindtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>

extern const u_char *packet;
char errBuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr *packet_header;
struct ether_header *ethernet_header;
int packetcount = 0;

void execute(){
    int choice;
    fp = fopen(config_path, "r");
    
    printf("请问是否采用配置文件?\n");
    printf("1.使用配置文件\n");
    printf("2.手动输入\n");
    printf("输入您的选择:");
    scanf("%d", &choice);
    
    switch (choice) {
        case 1:
            autotest();
            printf("已完成配置文件数据调用\n");
            break;
        case 2:
            handtest(devStr,path,condition,rule);
            printf("已完成配置文件数据输入\n");
            break;
        default:
            printf("未知选项\n");
            exit(1);
    }
    
    sleep(1);
    int maxcatch;
    printf("请设置最大捕获包数量:");
    scanf("%d",&maxcatch);
    char anwser;
    printf("请确认您的输入信息是否正确\n");
    printf("网卡:%s\n",devStr);
    printf("路径:%s\n",path);
    printf("状态:%s\n",condition);
    printf("正则:%s\n",rule);
    printf("数量:%d\n",maxcatch);
    
    printf("请问配置是否正确(y/n):");
    scanf(" %c", &anwser);
    if (anwser == 'y'|| anwser == 'Y'){
        printf("即将启动嗅探器...");
    } else if(anwser == 'n'|| anwser == 'N'){
        printf("即将返回重新修改...");
        sleep(1);
        handtest(devStr,path,condition,rule);
    } else {
        printf("无效输入,即将正常进行捕获...");
    }
    sleep(1);
    
    
    struct bpf_program fb;
    bpf_u_int32 net, mask;
    pcap_t *device; 
    if(strcmp(condition,"live")==0){
    device = pcap_open_live(devStr, BUFSIZ, 1, 1000, errBuf);
    if (pcap_compile(device, &fb, rule, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", rule, pcap_geterr(device));
    }
    if (pcap_setfilter(device, &fb) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", rule, pcap_geterr(device));
    }

    pcap_dumper_t* out_pcap;
    out_pcap  = pcap_dump_open(device,path);

    while (1) {
        packet = pcap_next(device, &packet_header);
        pcap_dump((u_char *)out_pcap, &packet_header, packet);
        if (packet == NULL) {
            printf("Sorry,No packet\n");
            continue;
        }
        ethernet_header = (struct ether_header*) packet;
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_ipv4_header(packet);
        } else if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_arp_header(packet);
        }  else {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            printf("Unknown packet type\n");
        }
        ++packetcount;
        if (packetcount >= maxcatch) {
            break;
        }
        sleep(1);
    }
    pcap_dump_close(out_pcap);
    pcap_close(device);
    }
    else {
    printf("You are offline!\n");
    device=pcap_open_offline(path,errBuf);
      while (pcap_next_ex(device, &packet_header, &packet) == 1) {
        if (packet == NULL) {
            printf("Error capturing packet\n");
            continue;
        }
        ethernet_header = (struct ether_header*) packet;
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_ipv4_header(packet);
        } 
        if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            print_arp_header(packet);
        } else {
            printf("\n\nPacket captured:\n");
            print_ethernet_header(packet);
            printf("Unknown packet type\n");
        }
    }
    pcap_close(device);
    }
}

