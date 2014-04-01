#include "../config.h"
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

#define USAGE_MAX_DLT 1024
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4
#define PCAP_THISZONE_OFFSET 8
#define PCAP_SIGFIGS_OFFSET 12
#define PCAP_SNAPLEN_OFFSET 16
#define PCAP_LINKTYPE_OFFSET 20

#define FLAG_THISZONE ( 1 << 0)
#define FLAG_SIGFIGS  ( 1 << 1)
#define FLAG_SNAPLEN  ( 1 << 2)
#define FLAG_LINKTYPE ( 1 << 3)

static void usage(const char *progname)
{
    int i;
    printf("Usage: %s [-h] [-l type] [-z zone] [-f sigfigs] [-s snaplen] file1.pcap ...\n", progname);
    puts("\tChange values in the  pcap header of the .pcap files\n");
    puts("\t-l type the linktype to set (decimal value)");
    puts("\t-z timezone the timezone value to set (decimal value)");
    puts("\t-f sigfigs the sigfigs value to set (decimal value)");
    puts("\t-s snaplen the snaplen to set (decimal value)");
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
    x |= (val & 0x00ff0000) >> 8;
    x |= (val & 0x0000ff00) << 8;
    x |= (val & 0x000000ff) << 24;

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

static int change_32bit(int fd, uint32_t new_val, off_t offset, int other_endian)
{
    uint32_t val;

    //swap it if the endian doesn't match
    val = other_endian ? new_val : reverse(new_val);
    
    if (lseek(fd, PCAP_LINKTYPE_OFFSET, SEEK_SET) != PCAP_LINKTYPE_OFFSET) {
        perror("Cannot seek to linktype offset");
        return -1;
    }

    if (write(fd, &val, sizeof val) != sizeof val) {
        perror("Writing new value failed");
        return -1;
    }

    fsync(fd);

    return 0;
}

int main(int argc, char *argv[])
{
    int c;
    uint32_t new_linktype = 0;
    uint32_t new_zone = 0;
    uint32_t new_sigfigs = 0;
    uint32_t new_snaplen = 0;
    int flags = 0;

    while ((c = getopt(argc, argv, "l:z:f:s:h")) != -1) {
        switch (c) {

            case 'l':
                new_linktype = atoi(optarg);
                flags |= FLAG_LINKTYPE;
                break;
            case 'z':
                new_zone = atoi(optarg);
                flags |= FLAG_THISZONE;
                break;
            case 'f':
                new_sigfigs = atoi(optarg);
                flags |= FLAG_SIGFIGS;
                break;
            case 's':
                new_snaplen = atoi(optarg);
                flags |= FLAG_SNAPLEN;
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

    if (!flags) {
        puts("Nothing to change");
        usage(argv[0]);
        return 1;
    }

    while (optind < argc) {
        int fd;
        int other_endian;

        fd = open_pcap(argv[optind], &other_endian);
        if (fd >= 0) {
            if (flags & FLAG_LINKTYPE) {
                change_32bit(fd, new_linktype, PCAP_LINKTYPE_OFFSET, other_endian);
            }
            if (flags & FLAG_THISZONE) {
                change_32bit(fd, new_zone, PCAP_THISZONE_OFFSET, other_endian);
            }
            if (flags & FLAG_SIGFIGS) {
                change_32bit(fd, new_sigfigs, PCAP_SIGFIGS_OFFSET, other_endian);
            }
            if (flags & FLAG_SNAPLEN) {
                change_32bit(fd, new_snaplen, PCAP_SNAPLEN_OFFSET, other_endian);
            }

            close(fd);
        }
        optind++;
    }

    return 0;
}
