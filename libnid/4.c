#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <nids.h>
#include <netinet/tcp.h>
#include <sys/time.h>

MYSQL *conn;

void dump_packet(struct tcp_stream *tcp, void **arg)
{
    MYSQL_STMT *stmt;
    MYSQL_BIND bind[5];
    char query[1024];

    if (tcp->nids_state == NIDS_JUST_EST)
    {
        printf("New TCP connection\n");
    }
    else if (tcp->nids_state == NIDS_CLOSE)
    {
        printf("TCP connection closed\n");
    }
    else if (tcp->nids_state == NIDS_DATA)
    {
        MYSQL_TIME timestamp;
        timestamp.year = tcp->timestamp.tv_sec / 31536000 + 1970;
        timestamp.month = tcp->timestamp.tv_sec % 31536000 / 2592000 + 1;
        timestamp.day = tcp->timestamp.tv_sec % 2592000 / 86400 + 1;
        timestamp.hour = tcp->timestamp.tv_sec % 86400 / 3600;
        timestamp.minute = tcp->timestamp.tv_sec % 3600 / 60;
        timestamp.second = tcp->timestamp.tv_sec % 60;
        timestamp.second_part = tcp->timestamp.tv_usec;

        sprintf(query, "INSERT INTO packets (timestamp, protocol, source_ip, destination_ip, data) VALUES (?, ?, ?, ?, ?)");

        stmt = mysql_stmt_init(conn);
        mysql_stmt_prepare(stmt, query, strlen(query));

        memset(bind, 0, sizeof(bind));
        bind[0].buffer_type = MYSQL_TYPE_DATETIME;
        bind[0].buffer = (char *)&timestamp;
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = tcp->nids_state == NIDS_DATA ? "TCP" : "UNKNOWN";
        bind[2].buffer_type = MYSQL_TYPE_STRING;
        bind[2].buffer = tcp->addr.saddr;
        bind[3].buffer_type = MYSQL_TYPE_STRING;
        bind[3].buffer = tcp->addr.daddr;
        bind[4].buffer_type = MYSQL_TYPE_LONG_BLOB;
        bind[4].buffer = tcp->data;
        bind[4].buffer_length = tcp->count;

        mysql_stmt_bind_param(stmt, bind);
        mysql_stmt_execute(stmt);
        mysql_stmt_close(stmt);
    }
}

int main()
{
    struct nids_chksum_ctl ctl;
    struct bpf_program *filter;
    char errbuf[PCAP_ERRBUF_SIZE];

    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, "localhost", "user", "password", "database", 0, NULL, 0))
    {
        fprintf(stderr, "Error: %s\n", mysql_error(conn));
        exit(1);
    }

    if (nids_init() == -1)
    {
        fprintf(stderr, "Error: %s\n", nids_errbuf);
        exit(1);
    }

    ctl.netaddr = 0;
    ctl.mask = 0;
    ctl.action = NIDS_DONT_CHKSUM;
    nids_register_chksum_ctl(&ctl, 1);

    filter = malloc(sizeof(struct bpf_program));
    nids_params.pcap_filter = "tcp or udp or arp or (ether[12:2]=0x0800 and (ip proto 1 or ip proto 6 or ip proto 17))";
    if (nids_init() == -1)
    {
        fprintf(stderr, "Error: %s\n", nids_errbuf);
        exit(1);
    }
    nids_compile_pcap_filter(filter, nids_params.pcap_filter, 0);
    nids_pcap_filter(filter);

    nids_register_tcp(dump_packet, (void **)&conn);
    nids_run();

    mysql_close(conn);

    return 0;
}