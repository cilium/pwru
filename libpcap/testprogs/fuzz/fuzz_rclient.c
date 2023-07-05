#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <pcap/pcap.h>

FILE * outfile = NULL;
struct pcap_rmtauth auth;

void fuzz_openFile(const char * name) {
    if (outfile != NULL) {
        fclose(outfile);
    }
    outfile = fopen(name, "w");
    auth.type = RPCAP_RMTAUTH_PWD;
    auth.username = "user";
    auth.password = "pass";
}

void sock_initfuzz(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    struct pcap_stat stats;
    int r;

    //initialization
    if (outfile == NULL) {
        fuzz_openFile("/dev/null");
    }

    sock_initfuzz(Data, Size);
    //initialize structure
    pkts = pcap_open("rpcap://127.0.0.1/fuzz.pcap", 0, 0, 1000, &auth, errbuf);
    if (pkts == NULL) {
        fprintf(outfile, "Couldn't open pcap file %s\n", errbuf);
        return 0;
    }

    //loop over packets
    r = pcap_next_ex(pkts, &header, &pkt);
    while (r > 0) {
        fprintf(outfile, "packet length=%d/%d\n",header->caplen, header->len);
        r = pcap_next_ex(pkts, &header, &pkt);
    }
    if (pcap_stats(pkts, &stats) == 0) {
        fprintf(outfile, "number of packets=%d\n", stats.ps_recv);
    }
    //close structure
    pcap_close(pkts);

    return 0;
}
