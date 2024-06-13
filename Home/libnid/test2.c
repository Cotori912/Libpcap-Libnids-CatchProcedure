#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <nids.h>

#define MAX_PACKETS 100

int packetCount = 0;

void processPacket(struct tcp_stream *tcp, void **arg) {
    struct ip *ipHeader = (struct ip *)tcp->packet;
    
    // 判断协议类型
    switch (ipHeader->ip_p) {
        case IPPROTO_UDP:
            printf("UDP packet\n");
            // 在这里添加UDP协议处理逻辑
            break;
        case IPPROTO_ICMP:
            printf("ICMP packet\n");
            // 在这里添加ICMP协议处理逻辑
            break;
        case IPPROTO_IP:
            printf("IP packet\n");
            // 在这里添加IP协议处理逻辑
            break;
        case IPPROTO_ARP:
            printf("ARP packet\n");
            // 在这里添加ARP协议处理逻辑
            break;
        default:
            printf("Unknown protocol\n");
    }
    
    packetCount++;
    if (packetCount >= MAX_PACKETS) {
        nids_exit();
    }
}

int main() {
    // 初始化libnids
    if (!nids_init()) {
        fprintf(stderr, "Error initializing libnids\n");
        exit(1);
    }

    // 设置回调函数
    nids_register_tcp(processPacket);

    // 开始捕获数据包
    nids_run();

    printf("Captured %d packets\n", packetCount);

    return 0;
}