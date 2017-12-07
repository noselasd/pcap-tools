#include "../config.h"
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <getopt.h>

/* Small utility to duplicate packets in pcap files */
struct Options {
    int count_n;//how many times to duplicate
    int change_ip;
    const char *in_file;
    const char *out_file;
};

static void change_ethpacket(struct pcap_pkthdr *hdr, unsigned char *packet)
{
    int vlanlen = 0;
    int ip_start;

    if (hdr->caplen < 24) {  //at least ethernet/ip hdr
        return;
    }

    if (packet[12] == 0x81 && packet[13] == 0) { //vlan
            vlanlen = 4;
    }
    if (packet[12 + vlanlen] != 0x08 && packet[12 + vlanlen] != 0) { //not ethtype for ipv4
        return;
    }
    ip_start = 14 + vlanlen;
    if ((packet[ip_start] & 0xf0) != 0x40 ) { //not ipv4
        return;
    }

    if (hdr->caplen < ip_start + 20) {
        return;
    }

   uint32_t *ip_src = (uint32_t *)&packet[ip_start + 12];
   uint32_t *ip_dst = (uint32_t *)&packet[ip_start + 16];


   *ip_src = htonl(ntohl(*ip_src) + 1);
   *ip_dst = htonl(ntohl(*ip_dst) + 1);

}

static void pcap_duplicate(struct Options *opts)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *in_pcap;
    pcap_t *out_pcap;
    pcap_dumper_t *dumper;
    int datalink;

    in_pcap = pcap_open_offline(opts->in_file, errbuf);
    if (in_pcap == NULL) {
        printf("Error opening %s: %s\n", opts->in_file, errbuf);
        return;
    }
    datalink = pcap_datalink(in_pcap);
    out_pcap = pcap_open_dead(datalink, pcap_snapshot(in_pcap));
    if (out_pcap == NULL) {
        pcap_close(in_pcap);
        puts("Error calling pcap_open_dead())");
        return;
    }
    dumper = pcap_dump_open(out_pcap, opts->out_file);
    if (dumper == NULL) {
        printf("Error opening output %s: %s\n", opts->out_file, pcap_geterr(out_pcap));
        pcap_close(in_pcap);
        pcap_close(out_pcap);
        return;
    }


    struct pcap_pkthdr hdr; 
    const unsigned char *packet;
    while ((packet = pcap_next(in_pcap, &hdr)) != NULL) {
        int i;
        for (i = 0; i < opts->count_n; i++) {
            if (opts->change_ip && datalink == DLT_EN10MB) { 
                change_ethpacket(&hdr, (unsigned char *)packet); //cast a way const ok.
            }
            pcap_dump((u_char*)dumper, &hdr, packet);
        }
    }


    pcap_dump_close(dumper);
    pcap_close(in_pcap);
    pcap_close(out_pcap);
}

static void usage(const char *progname)
{
    printf("Usage: %s [-hi] -n count -o output.pcap file.pcap\n", progname);
    puts("\t-n count  Duplicate each packet 'count' times");
    puts("\t-o output.pcap write output to this file");
    puts("\t-i alter the IP addresses for each time a packet is duplicated");
    puts("\t-h this help");
    printf("\t%s version %s using %s\n", progname, PACKAGE_VERSION, pcap_lib_version());
}

int main(int argc, char *argv[])
{
    int c;
    struct Options opts = {};

    while ((c = getopt(argc, argv, "o:n:hi")) != -1) {
        switch (c) {
            case 'o':
                opts.out_file = optarg;
                break;
            case 'n':
                opts.count_n = atoi(optarg);
                break;
            case 'i':
                opts.change_ip = 1;
                break;
            default: //fallthru
                printf("unknown option %c\n", c);
            case 'h':
                usage(argv[0]);
                return 1;
            break;
        }
    }

    if (optind == argc) {
        puts("No input files");
        usage(argv[0]);
        return 1;
    }
    
    if (opts.count_n <= 0) {
        puts("Invalid argument for -n");
        usage(argv[0]);
        return 2;
    }

    if (opts.out_file == NULL) {
        puts("Missing -o output.pcap argument");
        usage(argv[0]);
        return 2;
    }
    opts.in_file = argv[optind];

    pcap_duplicate(&opts);

    return 0;
}
