#include <stdio.h>
#include <pcap.h>

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char fname[50] = "/home/fcp/libr3s/pcap/tcp-ethereal-file1.trace";
    pcap_t *pcap;

    pcap_open_offline(fname, errbuf);
    while (pcap != NULL)
    {
        printf("packet %p\n", pcap++);
    }
    
    return(0);
}