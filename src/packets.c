#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <linux/if_packet.h>

#include "packets.h"


/* Maximum number of bytes to accept the message  */
#define BYTES 65536

/* IPv4 header length */
#define IP4_HDRLEN 20

/* List of IP protocol numbers (/etc/protocols) */
#define ICMP 1
#define TCP 6
#define UDP 17


/*
 * Function that collect all packages into log file.
 * */
void sniffer(char *interface)
{
    int sock_r, saddr_len, buf_len;
    unsigned char *buffer = (unsigned char *)malloc(BYTES);
    struct ifreq ifr;
    struct sockaddr saddr;
    struct sockaddr_ll sll;

    memset(buffer, 0, BYTES);
    memset(&ifr, 0, sizeof(ifr));
    memset(&sll, 0, sizeof(sll));

    FILE *logfile = fopen("/var/log/netflow-exporter.log", "w");

    sock_r = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (sock_r < 0) {
        fprintf(stderr, "Error: Can't open socket\n");
        exit(EXIT_FAILURE);
    }

    strncpy((char *)ifr.ifr_name, interface, IFNAMSIZ);

    if (ioctl(sock_r, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "Error: Unable to find interface index\n");
        exit(EXIT_FAILURE);
    }

    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_IP);

    if (bind(sock_r, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
        fprintf(stderr, "Errro: Can't bind socket to specific interface\n");
        exit(EXIT_FAILURE);
    }
    
    while (1) {
        saddr_len = sizeof(saddr);
        buf_len = recvfrom(sock_r, buffer, BYTES, 0, &saddr, (socklen_t *)&saddr_len);

        if (buf_len < 0) {
            fprintf(stderr, "Error: Can't read data from recvfrom function\n");
            exit(EXIT_FAILURE);
        }
        
        data_process(buffer, logfile);
        fflush(logfile);
    }
    close(sock_r);
    fclose(logfile);
    free(buffer);
}


/*
 * Sniffs all packets that arrive on a given network interface (ICMP/TCP/UDP). 
 * */
void data_process(unsigned char *buffer, FILE* logfile)
{
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    switch (ip->protocol) {
        case TCP:
            tcp_header(buffer, logfile);
            break;
        case UDP:
            udp_header(buffer, logfile);
            break;
        case ICMP:
            icmp_header(buffer, logfile);
            break;
    }
}


/*
 * Writes information about ICMP packets into the log file.
 * */
void icmp_header(unsigned char *buffer, FILE* logfile)
{
    char ip_source[16], ip_dest[16];
    struct sockaddr_in source, dest;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct icmphdr *icmp = (struct icmphdr *)(buffer + IP4_HDRLEN);

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    strncpy(ip_source, inet_ntoa(source.sin_addr), sizeof(ip_source));
    strncpy(ip_dest, inet_ntoa(dest.sin_addr), sizeof(ip_dest));

    fprintf(logfile,
            "Protocol: ICMP (%d) \t Version: %d \t Type Of Service: %d \t Total Length: %d \t Identificator: %d \t \
            ICMP Type: %d \t Source: %s \t Destination: %s \t TTL: %d\n",
            (unsigned int)ip->protocol, (unsigned int)ip->version,
            (unsigned int)ip->tos, ntohs(ip->tot_len), ntohs(ip->id), icmp->type,
            ip_source, ip_dest, (unsigned int)ip->ttl);
}


/*
 * Writes information about TCP packets into the log file.
 * */
void tcp_header(unsigned char *buffer, FILE* logfile)
{
    char ip_source[16], ip_dest[16];
    struct sockaddr_in source, dest;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    int iphdrlen = ip->ihl*4;
    struct tcphdr *tcp = (struct tcphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    
    strncpy(ip_source, inet_ntoa(source.sin_addr), sizeof(ip_source));
    strncpy(ip_dest, inet_ntoa(dest.sin_addr), sizeof(ip_dest));

    fprintf(logfile,
            "Protocol: TCP (%d) \t Version: %d \t Type Of Service: %d \t Total Length: %d \t \
            Identificator: %d \t Source: %s \t Destination: %s \t TTL: %d\n",
            (unsigned int)ip->protocol, (unsigned int)ip->version,
            (unsigned int)ip->tos, ntohs(ip->tot_len), ntohs(ip->id),
            ip_source, ip_dest, (unsigned int)ip->ttl);
    
    fprintf(logfile,
            "\tSource port:  %d \t Destination port: %d \t Sequence number: %d \t Acknowledge number: %d\n",
            ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq));
    
    fprintf(logfile,
            "\tUrgent flag: %d \t Acknowledge flag: %d \t Push flag: %d \t Reset flag: %d \t \
            Synchronise flag: %d \t Finish flag: %d \t Window size: %d \t Checksum: %d \t Urgent pointer: %d\n",
            (unsigned int)tcp->urg, (unsigned int)tcp->ack, (unsigned int)tcp->psh,
            (unsigned int)tcp->rst, (unsigned int)tcp->syn, (unsigned int)tcp->fin,
            ntohs(tcp->window), ntohs(tcp->check), tcp->urg_ptr);
}


/*
 * Writes information about UDP packets into the log file.
 * */
void udp_header(unsigned char *buffer, FILE* logfile)
{
    char ip_source[16], ip_dest[16];
    struct sockaddr_in source, dest;
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    int iphdrlen = ip->ihl*4;
    struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;
    
    strncpy(ip_source, inet_ntoa(source.sin_addr), sizeof(ip_source));
    strncpy(ip_dest, inet_ntoa(dest.sin_addr), sizeof(ip_dest));

    fprintf(logfile,
            "Protocol: UDP (%d) \t Version: %d \t Type Of Service: %d \t Total Length: %d \t \
            Identificator: %d \t Source: %s \t Destination: %s \t TTL: %d\n",
            (unsigned int)ip->protocol, (unsigned int)ip->version,
            (unsigned int)ip->tos, ntohs(ip->tot_len), ntohs(ip->id),
            ip_source, ip_dest, (unsigned int)ip->ttl);
    
    fprintf(logfile,
            "\tSource port:  %d \t Destination port: %d \t UDP Length: %d \t UDP Checksum: %d\n",
            ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len), ntohs(udp->check));
}
