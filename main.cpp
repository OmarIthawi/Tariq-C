#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <pcap.h>  /* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */

using namespace std;

int main(int argc, char **argv) {
    char *dev = (char*) "eth2";
    char *net;
    char *mask;
    
    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    
    struct in_addr addr;
    
    // dev = pcap_lookupdev(errbuf);
    
    if (dev == NULL) {
        cout << "Dev = NULL";
        exit(1);
    }
    
    printf("Dev: %s\n", dev);
    
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    
    if (ret == -1) {
        printf("%s\n", errbuf);
        exit(1);
    }
    
    addr.s_addr = netp;
    
    net = inet_ntoa(addr);
    
    if (net == NULL) {
        perror("inet_ntoa");
    }
    
    printf("Net: %s\n", net);
    
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);
    
    if (mask == NULL) {
        perror("inet_ntoa");
    }
    
    printf("Mask: %s\n", mask);
    
    return 0;
}

