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
    clear();
    printw("The List of useful NetworkCard：\n");

    // 遍历网卡列表
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // 仅输出IPv4和IPv6网卡信息
        if (family == AF_INET || family == AF_INET6) {
            if (getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                printw("[%d] %s: %s\n", n, ifa->ifa_name, host);
            } else {
                printw("[%d] %s\n", n, ifa->ifa_name);
            }
        }
    }

    freeifaddrs(ifaddr);

}

void autotest() {
    printw("Running config.txt...\n");
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

/**void handtest(char devStr[], char path[], char condition[], char rule[])**/
void handtest() {
    
    printw("Please set the parameter:\n");
    printw("Will show the useful NetworkCard soon...\n");
    findnet();
    
    sleep(1);
    
    printw("Please choose the NetworkCard:(Such as eth0):");
    scanw(" %s", devStr);
    
    printw("Please set the Save Path(Such as ./packet/pack.pcap):");
    scanw(" %s", path);
    
    printw("Please choose the condition(live or offline):");
    scanw(" %s", condition);
    
    printw("Please set the rule(Such as:ip tcp ):");
    scanw(" %s", rule);
}


