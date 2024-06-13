#include "lcpexecute.h"
#include "lcpfindtest.h"
#include <ncurses.h>
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
struct pcap_pkthdr packet_header;
struct ether_header *ethernet_header;
int packetcount = 0;


void execute(){
    int i;
    int choice;
    int highlight = 1;
    int c;
    int maxcatch;
    char anwser;
    int ch;
    pcap_t *device;
    pcap_dumper_t* out_pcap;
    
    char *menu[] = {
        "Config File Set",
        "Set by User"
    };
    
    int menu_length = sizeof(menu) / sizeof(menu[0]);
    
    fp = fopen(config_path, "r");
    
    while (1) {
        clear();
        for ( i = 0; i < menu_length; i++) {
            if (i + 1 == highlight) {
                attron(A_REVERSE);
            }
            mvprintw(i + 1, 1, "%s", menu[i]);
            attroff(A_REVERSE);
        }

        c = getch();
        switch (c) {
            case KEY_UP:
                if (highlight > 1) {
                    highlight--;
                }
                break;
            case KEY_DOWN:
                if (highlight < menu_length) {
                    highlight++;
                }
                break;
            case '\n':
                choice = highlight;
                break;
        }
    
    switch (choice) {
        case 1: {
        autotest();
        clear();  // 清空窗口
        mvprintw(3,0,"Get Ready to Start...");
        getch();
        clear();
        mvprintw(3,0,"Please set the maxcatch:");
        scanw("%d",&maxcatch);
        refresh();
        getch();
        clear();
        mvprintw(1,0,"Please make sure the message is right:");
        mvprintw(2,0,"Network Card:%s",devStr);
        mvprintw(3,0,"Path:%s",path);
        mvprintw(4,0,"Condition:%s",condition);
        mvprintw(5,0,"Rule:%s",rule);
        mvprintw(6,0,"Maxcatch:%d",maxcatch);
        mvprintw(7,0,"Y or N:",maxcatch);
        scanw("%c",&anwser);
        refresh();
        getch();
        clear();
        if (anwser == 'y'|| anwser == 'Y'){
            printw("Running...");
            refresh();
            struct bpf_program fb;
            bpf_u_int32 net, mask;
            if(strcmp(condition,"live")==0){
                device = pcap_open_live(devStr, BUFSIZ, 1, 1000, errBuf);
            }
            else {
                printw("You are offline!\n");
                device=pcap_open_offline(path,errBuf);
            }
            out_pcap  = pcap_dump_open(device,path);
            if (pcap_compile(device, &fb, rule, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", rule, pcap_geterr(device));
            }
            if (pcap_setfilter(device, &fb) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", rule, pcap_geterr(device));
            }

            while(/**packetcount != maxcatch**/1){
                /**packetcount++;**/
                packet=pcap_next(device,&packet_header);
                /**pcap_dump((u_char *)out_pcap, &packet_header, packet);**/
                if (packet == NULL) {
                    printw("Error capturing packet\n");
                }
                    ethernet_header = (struct ether_header*) packet;
                if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
                    printw("\n\nPacket captured:\n");
                    print_ethernet_header(packet);
                    print_ip_header(packet);
                    refresh();
                } 
                if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
                    printw("\n\nPacket captured:\n");
                    print_ethernet_header(packet);
                    print_arp_header(packet);
                    refresh();
                } else {
                    printw("\n\nPacket captured:\n");
                    print_ethernet_header(packet);
                    printw("Unknown packet type\n");
                    refresh();
                }
                ch = getch();
                while(ch != '\n') {
                    if (ch == 'q') {
                    break;
                    }
                }
    }
}else {
    goto Step1;
}
break;
}
        
    case 2:{
Step1:
        handtest();
        clear();
            refresh();
            struct bpf_program fb;
            bpf_u_int32 net, mask;
            if(strcmp(condition,"live")==0){
                device = pcap_open_live(devStr, BUFSIZ, 1, 1000, errBuf);
            }
            else {
                printw("You are offline!\n");
                device=pcap_open_offline(path,errBuf);
            }
            pcap_dumper_t* out_pcap;
            if (pcap_compile(device, &fb, rule, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", rule, pcap_geterr(device));
            }
            if (pcap_setfilter(device, &fb) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", rule, pcap_geterr(device));
            }

            while(/**packetcount != maxcatch**/1){
                /**packetcount++;**/
                packet=pcap_next(device,&packet_header);
                if (packet == NULL) {
                    printw("Error capturing packet\n");
                }
                    ethernet_header = (struct ether_header*) packet;
                if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
                    printw("\n\nPacket captured:\n");
                    print_ethernet_header(packet);
                    print_ip_header(packet);
                    refresh();
                } 
                if (ntohs(ethernet_header->ether_type) == ETHERTYPE_ARP) {
                    printw("\n\nPacket captured:\n");
                    print_ethernet_header(packet);
                    print_arp_header(packet);
                    refresh();
                } else {
                    printw("\n\nPacket captured:\n");
                    print_ethernet_header(packet);
                    printw("Unknown packet type\n");
                    refresh();
                }
                ch = getch();
                while(ch != '\n') {
                    if (ch == 'q') {
                    break;
                    }
                }
    }
    }
    pcap_close(device);
    endwin();
}
}
}


