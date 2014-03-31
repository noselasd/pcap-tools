#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <errno.h>

/* Small utility to show info and dump the hex content of 
 * pcap files */

static int count_packets;
#define USAGE_MAX_DLT 1024
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_LINKTYPE_OFFSET 20
static void usage(const char *progname)
{
    int i;
    printf("Usage: %s [-h] -l type file1.pcap file2.pcap ...\n", progname);
    puts("\tChange the pcap linktype of the .pcap files\n");
    puts("\t-l type the link type to set (decimal value)");
    puts("\nKnown linktypes are:");

    for (i = 0; i < USAGE_MAX_DLT; i++) {
        const char *name = pcap_datalink_val_to_name(i);
        const char *desc = pcap_datalink_val_to_description(i);
        if (name) {
            printf("%-4d %s (%s)\n", i, desc, name);
        }
    }
}

static uint32_t reverse(uint32_t val)
{
    uint32_t x;

    x =  (val & 0xff000000) >> 24;
    x |= (val & 0x00ff0000) >> 16;
    x |= (val & 0x0000ff00) >> 8;
    x |= (val & 0x000000ff);

    return x;
}

static int open_pcap(const char *file, int *other_endian)
{
    int fd;
    uint32_t magic;

    fd = open(file, O_RDWR);
    if (fd < 0) {
        printf("Cannot open %s : %s\n", file, strerror(errno));
        return -1;
    }

    if (read(fd, &magic, sizeof magic) != sizeof magic) {
        perror("Short read");
        close(fd);
        return -1;
    }

    if (magic != PCAP_MAGIC_NUMBER && reverse(magic) != PCAP_MAGIC_NUMBER) {
        printf("%s is not a known pcap file\n", file);
        close(fd);
        return -1;
    }

    *other_endian = magic != PCAP_MAGIC_NUMBER;

    return fd;
}

static void change_linktype(const char *file, uint32_t new_linktype)
{
    int fd;
    uint32_t linktype;
    int other_endian;

    if ((fd = open_pcap(file, &other_endian)) == -1) {
        return;
    }
   
    //swap it if the endian doesn't match
    linktype = other_endian ? new_linktype : reverse(new_linktype);
    
    if (lseek(fd, PCAP_LINKTYPE_OFFSET, SEEK_SET) != PCAP_LINKTYPE_OFFSET) {
        perror("Cannot seek to linktype offset");
        close(fd);
    }

    if (write(fd, &linktype, sizeof new_linktype) != sizeof new_linktype) {
        perror("Writing new linktype failed");
        close(fd);
        return;
    }

    fsync(fd);
    close(fd);

    printf("Changed linktype on %s to %u\n", file, (unsigned) new_linktype);
}

int main(int argc, char *argv[])
{
    int c;
    uint32_t new_linktype;
    int got_linktype = 0;

    while ((c = getopt(argc, argv, "l:h")) != -1) {
        switch (c) {

            case 'l':
                count_packets = 1;
                got_linktype = 1;
                new_linktype = atoi(optarg);
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

    if (!got_linktype) {
        puts("Missing -l linktype");
        usage(argv[0]);
        return 1;
    }

    while (optind < argc) {
        change_linktype(argv[optind], new_linktype);
        optind++;
    }

    return 0;
}
