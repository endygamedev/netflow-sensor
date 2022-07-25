#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "common.h"
#include "packets.h"


int main(int argc, char **argv)
{
    char *interface = NULL;
    char *in_address = NULL;
    int c;

    while ((c = getopt(argc, argv, "i:n:")) != -1) {
        switch (c) {
            case 'i':
                interface = optarg;
                break;
            case 'n':
                in_address = optarg;
                break;
            case '?':
                if (optopt == 'i' || optopt == 'n') {
                    fprintf(stderr, "Error: Option [-%c] requires an argument\n",
                                                                        optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "Error: Unknown option [-%c]\n", optopt);
                } else {
                    fprintf(stderr, "Error: Unknown option character [-\\x%x]\n", optopt);
                }
                exit(EXIT_FAILURE);
            default:
                abort();
        }
    }

    if (interface == NULL || in_address == NULL) {
        fprintf(stderr, "Usage: exporter -i <network interface> -n <ip_address>:<port>\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in coll_addr = init_address(in_address, AF_INET);
    
    fprintf(stdout, "IP-address of Netflow Collector: %s:%d\n",
            inet_ntoa(coll_addr.sin_addr), ntohs(coll_addr.sin_port));

    for (int i = optind; i < argc; i++) {
        fprintf(stderr, "Warning: Non-option argument `%s`\n", argv[i]);
    }
    
    sniffer(interface);

    return EXIT_SUCCESS;
}
