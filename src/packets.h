#pragma once

void sniffer(char *interface);
void icmp_header(unsigned char *buffer, FILE* logfile);
void tcp_header(unsigned char *buffer, FILE* logfile);
void udp_header(unsigned char *buffer, FILE* logfile);
void data_process(unsigned char *buffer, FILE* logfile);
