#include "../config.h"
#include <pcap.h>
#include <getopt.h>

/* Small utility to show info and dump the hex content of 
 * pcap files */

static int count_packets;
static int print_hex;

static void dump_hex(const unsigned char *data, u_int len)
{
    u_int i;
    for (i = 1; i <= len; i++) {
        printf("%02X ", data[i - 1]);
        if (i % 20 == 0)
            putchar('\n');
    }

    if (i % 20 != 0)
        putchar('\n');
   putchar('\n');

}

static void pcap_duplicate(int n, const char *file, const char *out_file)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *in_pcap;
    pcap_t *out_pcap;
    pcap_dumper_t *dumper;

    in_pcap = pcap_open_offline(file, errbuf);
    if (in_pcap == NULL) {
        printf("Error opening %s: %s\n", file, errbuf);
        return;
    }

    out_pcap = pcap_open_dead(pcap_datalink(in_pcap), pcap_snapshot(in_pcap));
    if (out_pcap == NULL) {
        pcap_close(in_pcap);
        puts("Error calling pcap_open_dead())");
        return;
    }
    dumper = pcap_dump_open(in_pcap, out_file);
    if (dumper == NULL) {
        pcap_close(in_pcap);
        pcap_close(out_pcap);
        printf("Error opening %s: %s\n", file, errbuf);
        return;
    }


    struct pcap_pkthdr hdr; 
    const unsigned char *packet;
    while ((packet = pcap_next(in_pcap, &hdr)) != NULL) {
        int i;
        for (i = 0; i < n; i++) {
            pcap_dump(dumper, &hdr, packet);
        }
    }


    pcap_dump_close(dumper);
    pcap_close(in_pcap);
    pcap_close(out_pcap);
}

static void usage(const char *progname)
{
    printf("Usage: %s [-h] -n count -o output.pcap file.pcap\n", progname);
    puts("\t-n count  Duplicate each packet 'count' times\n");
    puts("\t-h this help");
    printf("\t%s version %s using %s\n", progname, PACKAGE_VERSION, pcap_lib_version());
}

int main(int argc, char *argv[])
{
    int c;
    int count_n = -1;
    const char *out_file = NULL;

    while ((c = getopt(argc, argv, "o:n:h")) != -1) {
        switch (c) {
            case 'o':
                out_file = optarg;
                break;
            case 'n':
                count_n = atoi(optarg);
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
    
    if (count_n <= 0) {
        puts("Invalid argument for -n");
        usage(argv[0]);
        return 2;
    }

    if (out_file == NULL) {
        puts("Missing -o output.pcap argument");
        usage(argv[0]);
        return 2;
    }

    pcap_duplicate(count_n, argv[optind], out_file);

    return 0;
}
