#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"


/* Maximum number of ports */
#define MAX_PORT 65535


/*
 * Checks if the string is a number.
 * Returns 1 if string is a number, 0 otherwise.
 * */
int is_number(char *arg)
{
    int flag = 1;
    for (int i = 0; i < (int)strlen(arg); i++) {
        if (!isdigit(arg[i])) {
            flag = 0;
            break;
        }
    }
    return flag;
}


/*
 * Checks if IP record is valid or not.
 * Returns EXIT_SUCCESS if all correct, EXIT_FAILURE otherwise.
 * */
int check_ip_record(char *ip)
{
    if (ip == NULL) {
        return EXIT_SUCCESS;
    }
    
    char *tmp = strdup(ip);

    char *token = strtok(tmp, ".");
    int number, count = 0;

    while (token != NULL) {
        if (count > 3) {
            fprintf(stderr, "Error: Invalid IP address\n");
            exit(EXIT_FAILURE);
        }
        
        if (!is_number(token)) {
            fprintf(stderr, "Error: Invalid IP address\n");
            exit(EXIT_FAILURE);
        }
        
        number = atoi(token);
        
        if (number > 255 || number < 0) {
            fprintf(stderr, "Error: Invalid IP address\n");
            exit(EXIT_FAILURE);
        }

        token = strtok(NULL, ".");
        count++;
    }

    free(tmp);
    
    return EXIT_SUCCESS;
}


/*
 * Checks if UDP port is valid or not.
 * Returns EXIT_SUCCESS if all correct, EXIT_FAILURE otherwise.
 * */
int check_port(int port)
{
    if (port > MAX_PORT) {
        fprintf(stderr, "Error: Invalid UDP port\n");
        exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}


/*
 * Parse input collector address and initialize it.
 * Returns initialized collector address (sockaddr_in) if all correct, EXIT_FAILURE otherwise.
 * */
struct sockaddr_in init_address(char *in_address, int family)
{
    char *token;
    char *ip_address, str_port[4];
    int port;
    struct sockaddr_in address;
    
    token = strtok(in_address, ":");
    ip_address = strdup(token);
    
    token = strtok(NULL, ":");
    strcpy(str_port, token);
   
    if (is_number(str_port)) {
        port = atoi(str_port);
        check_port(port);
    } else {
        exit(EXIT_FAILURE);
    }

    check_ip_record(ip_address);

    address.sin_family = family;
    address.sin_port = htons(port);
    inet_pton(family, ip_address, &(address.sin_addr));

    free(ip_address);

    return address;
}
