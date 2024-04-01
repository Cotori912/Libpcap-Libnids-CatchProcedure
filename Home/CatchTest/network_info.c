#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main() {
    struct ifaddrs *ifaddr, *ifa;
    int family, n;
    char host[NI_MAXHOST];

    // 获取当前系统的网卡信息
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    printf("可用的网卡列表：\n");

    // 遍历网卡列表
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // 仅输出IPv4和IPv6网卡信息
        if (family == AF_INET || family == AF_INET6) {
            if (getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                printf("[%d] %s: %s\n", n, ifa->ifa_name, host);
            } else {
                printf("[%d] %s\n", n, ifa->ifa_name);
            }
        }
    }

    freeifaddrs(ifaddr);

    return 0;
}