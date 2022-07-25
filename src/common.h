#pragma once

#include <netinet/in.h>


int is_number(char *arg);
int check_ip_record(char *ip);
int check_port(int port);
struct sockaddr_in init_address(char *in_address, int family);
