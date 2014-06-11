#include "../config.h"
#include <pcap.h>
#include <getopt.h>

/* Small utility to show info and dump the hex content of 
 * pcap files */

static int count_packets;
static int print_hex;

static void usage(const char *progname)
{
    printf("Usage: %s [-hcp] file1.pcap file2.pcap ...\n", progname);
    puts("\t-c count the number of packets");
    puts("\t-p print a hex dump of each packet");
    puts("\t-h this help");
    printf("\t%s version %s using %s\n", progname, PACKAGE_VERSION, pcap_lib_version());
}

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

static void pcap_info(const char *file)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;

    pcap = pcap_open_offline(file, errbuf);
    if (pcap == NULL) {
        printf("Error opening %s: %s\n", file, errbuf);
        return;
    }

    printf("%s : pcap version_major %u pcap version_minor %u link_type %s (%d decimal)\n", 
            file, 
            pcap_major_version(pcap),
            pcap_minor_version(pcap),
            pcap_datalink_val_to_name(pcap_datalink(pcap)),
            pcap_datalink(pcap));

    if (count_packets || print_hex) {
        unsigned int count = 0;
        struct pcap_pkthdr hdr; 
        const unsigned char *packet;

        while ((packet = pcap_next(pcap, &hdr)) != NULL) {
            if (print_hex) {
                printf("packet %u\n", count);
                dump_hex(packet, hdr.len);
            }

            count++;
        }

        if (count_packets) {
            printf("Total packets: %u\n", count);
        }
    }

    pcap_close(pcap);
}

int main(int argc, char *argv[])
{
    int c;

    while ((c = getopt(argc, argv, "cph")) != -1) {
        switch (c) {

            case 'c':
                count_packets = 1;
                break;

            case 'p':
                print_hex = 1;
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
        usage(argv[0]);
        return 1;
    }

    while (optind < argc) {
        pcap_info(argv[optind]);
        optind++;
    }

    return 0;
}
