#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_LINE_LENGTH 100

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    printf("Received Packet Size: %d\n", pkthdr->len);
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
    if(strcmp(condition,"live")==0){
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    pcap_dumper_t* out_pcap;
    out_pcap  = pcap_dump_open(device,path);
     if (pcap_compile(device, &fp, rule, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", rule, pcap_geterr(device));
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(device, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", rule, pcap_geterr(device));
        return EXIT_FAILURE;
    }
    pcap_loop(device, 20, processPacket, (u_char *)out_pcap);
 
    pcap_dump_flush(out_pcap);
    
    pcap_dump_close(out_pcap);
    pcap_close(device);

    printf("devStr: %s\n", devStr);
    }
    else {
    printf("You are offline!\n");
    pcap_t *handle;
    handle=pcap_open_offline(path,errBuf);
    pcap_loop(handle,0,processPacket,NULL);
    pcap_close(handle);
    }
    return 0;
}