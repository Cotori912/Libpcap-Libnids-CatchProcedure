#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include "lcpfindtest.h"


FILE *fp;
char line[MAX_LINE_LENGTH];
char config_path[] = "config.txt";
char devStr[MAX_LINE_LENGTH];
char path[MAX_LINE_LENGTH];
char condition[MAX_LINE_LENGTH];
char rule[MAX_LINE_LENGTH];

void findnet() {
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

}

void autotest() {
    printf("Running config.txt...\n");
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
}

void handtest(char devStr[], char path[], char condition[], char rule[]) {
    
    printf("请依次输入您想要的参数\n");
    printf("即将为您显示可用网卡...\n");
    findnet();
    
    sleep(1);
    
    printf("请选择网卡(例如 eth0):");
    scanf(" %s", devStr);
    
    printf("请输入默认路径(例如 ./packet/pack.pcap):");
    scanf(" %s", path);
    
    printf("请输入程序状态(live or offline):");
    scanf(" %s", condition);
    
    printf("请设置捕获正则(例如 ip tcp ):");
    scanf(" %s", rule);
}


