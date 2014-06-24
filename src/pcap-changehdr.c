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
#include <inttypes.h>

/* Small utility to show info and dump the hex content of 
 * pcap files */

#define USAGE_MAX_DLT 1024
#define PCAP_MAGIC_NUMBER 0xA1B2C3D4

#define PCAP_MAGIC_OFFSET 0
#define PCAP_VERSION_MAJOR_OFFSET 4
#define PCAP_VERSION_MINOR_OFFSET 6
#define PCAP_THISZONE_OFFSET 8
#define PCAP_SIGFIGS_OFFSET 12
#define PCAP_SNAPLEN_OFFSET 16
#define PCAP_LINKTYPE_OFFSET 20

#define FLAG_MAGIC         ( 1 << 0)
#define FLAG_MAJOR_VERSION ( 1 << 1)
#define FLAG_MINOR_VERSION ( 1 << 2)
#define FLAG_THISZONE      ( 1 << 3)
#define FLAG_SIGFIGS       ( 1 << 4)
#define FLAG_SNAPLEN       ( 1 << 5)
#define FLAG_LINKTYPE      ( 1 << 6)
#define FLAG_MAX           ( 1 << 7)

static uint32_t reverse32(uint32_t val);
static uint16_t reverse16(uint16_t val);
static int change_16bit(int fd, uint32_t new_val, off_t offset, int other_endian);
static int change_32bit(int fd, uint32_t new_val, off_t offset, int other_endian);
static uint32_t get_32bit(int fd, off_t offset, int other_endian);
static uint32_t get_16bit(int fd, off_t offset, int other_endian);


const struct {
    unsigned int flag;
    off_t file_offset;
    int (*change_func)(int fd, uint32_t new_val, off_t offset, int other_endian);
    uint32_t (*get_func)(int fd, off_t offset, int other_endian);
    const char *field_name;
} pcap_headers [] = {
    {
        FLAG_MAGIC,
        PCAP_MAGIC_OFFSET,
        change_32bit,
        get_32bit,
        "MAGIC"
    },
    {
        FLAG_MAJOR_VERSION,
        PCAP_VERSION_MAJOR_OFFSET,
        change_16bit,
        get_16bit,
        "MAJOR_VERSION"
    },
    {
        FLAG_MINOR_VERSION,
        PCAP_VERSION_MINOR_OFFSET,
        change_16bit,
        get_16bit,
        "MINOR_VERSION"
    },

    {
        FLAG_THISZONE,
        PCAP_THISZONE_OFFSET,
        change_32bit,
        get_32bit,
        "THISZONE"
    },

    {
        FLAG_SIGFIGS,
        PCAP_SIGFIGS_OFFSET,
        change_32bit,
        get_32bit,
        "SIGFIGS"
    },

    {
        FLAG_SNAPLEN,
        PCAP_SNAPLEN_OFFSET,
        change_32bit,
        get_32bit,
        "SNAPLEN"
    },
    {
        FLAG_LINKTYPE,
        PCAP_LINKTYPE_OFFSET,
        change_32bit,
        get_32bit,
        "LINKTYPE"
    }

};


static void show_linktypes(void)
{
    int i;
    puts("\nKnown linktypes are:");
    for (i = 0; i < USAGE_MAX_DLT; i++) {
        const char *name = pcap_datalink_val_to_name(i);
        const char *desc = pcap_datalink_val_to_description(i);
        if (name) {
            printf("%-4d %s (%s)\n", i, desc, name);
        }
    }
}

static uint16_t reverse16(uint16_t val)
{
    uint16_t x;

    x =  (val & 0xff00) >> 8U;
    x |= (val & 0x00ff) << 8U;

    return x;
}

static uint32_t reverse32(uint32_t val)
{
    uint32_t x;

    x =  (val & 0xff000000) >> 24U;
    x |= (val & 0x00ff0000) >> 8U;
    x |= (val & 0x0000ff00) << 8U;
    x |= (val & 0x000000ff) << 24U;

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

    if (magic != PCAP_MAGIC_NUMBER && reverse32(magic) != PCAP_MAGIC_NUMBER) {
        printf("%s does not contain a known pcap signature\n", file);
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
    val = other_endian ? reverse32(new_val) : new_val;
    
    if (lseek(fd, offset, SEEK_SET) != offset) {
        perror("Cannot seek to header offset");
        return -1;
    }

    if (write(fd, &val, sizeof val) != sizeof val) {
        perror("Writing new value failed");
        return -1;
    }

    fsync(fd);

    return 0;
}

static int change_16bit(int fd, uint32_t new_val, off_t offset, int other_endian)
{
    uint16_t val;

    //swap it if the endian doesn't match
    val = other_endian ? reverse16((uint16_t)new_val) : (uint16_t)new_val;
    
    if (lseek(fd, offset, SEEK_SET) != offset) {
        perror("Cannot seek to header offset");
        return -1;
    }

    if (write(fd, &val, sizeof val) != sizeof val) {
        perror("Writing new value failed");
        return -1;
    }

    fsync(fd);

    return 0;
}

static uint32_t get_32bit(int fd, off_t offset, int other_endian)
{
    uint32_t val;

    //swap it if the endian doesn't match
    
    if (lseek(fd, offset, SEEK_SET) != offset) {
        perror("Cannot seek to header offset");
    }

    if (read(fd, &val, sizeof val) != sizeof val) {
        perror("reading new value failed");
    }
    val = other_endian ? reverse32(val) : val;


    return val;
}

static uint32_t get_16bit(int fd, off_t offset, int other_endian)
{
    uint16_t val;

    //swap it if the endian doesn't match
    
    if (lseek(fd, offset, SEEK_SET) != offset) {
        perror("Cannot seek to header offset");
    }

    if (read(fd, &val, sizeof val) != sizeof val) {
        perror("reading new value failed");
    }
    val = other_endian ? reverse16(val) : val;


    return val;
}

static void change_header(int fd, int other_endian, uint32_t flags, const uint32_t *new_vals)
{
    size_t i;

    for (i = 0; i < sizeof pcap_headers/sizeof pcap_headers[0]; i++) {
        if (flags & pcap_headers[i].flag) {
            off_t offset = pcap_headers[i].file_offset;
            uint32_t new_val = new_vals[pcap_headers[i].flag];
            pcap_headers[i].change_func(fd, new_val, offset, other_endian);
        }
    }
}

static void show_header(int fd, int other_endian)
{
    size_t i;

    for (i = 0; i < sizeof pcap_headers/sizeof pcap_headers[0]; i++) {
        off_t offset = pcap_headers[i].file_offset;
        uint32_t val;

        val = pcap_headers[i].get_func(fd, offset, other_endian);
        printf("%-15s: %" PRIu32 "\n",pcap_headers[i].field_name, val);
    }
}

static void usage(const char *progname)
{
    printf("Usage: %s [-h] options..  file1.pcap ...\n", progname);
    puts("\tChange values in the  pcap header of .pcap files\n");
    puts("\t The following arguments can be used:");
    puts("\t-l type     change the linktype (decimal value)");
    puts("\t-z timezone change the timezone value (decimal value)");
    puts("\t-f sigfigs  change the sigfigs value (decimal value)");
    puts("\t-s snaplen  change the snaplen (decimal value)");
    puts("\t-M version  change the major version to set (decimal value)");
    puts("\t-m version  change the minor version to set (decimal value)");
    puts("\t-I          show the pcap header fields");
    puts("\t-L          show the known values for 'linktype'");
    printf("\t%s version %s using %s\n", progname, PACKAGE_VERSION, pcap_lib_version());

}

int main(int argc, char *argv[])
{
    int c;
    uint32_t new_vals[FLAG_MAX -1];
    unsigned int flags = 0;
    int header_info = 0;
    int linktype_info = 0;

    while ((c = getopt(argc, argv, "l:z:f:s:M:m:ILh")) != -1) {
        switch (c) {

            case 'l':
                new_vals[FLAG_LINKTYPE] = atoi(optarg);
                flags |= FLAG_LINKTYPE;
                break;
            case 'z':
                new_vals[FLAG_THISZONE] = atoi(optarg);
                flags |= FLAG_THISZONE;
                break;
            case 'f':
                new_vals[FLAG_SIGFIGS] = atoi(optarg);
                flags |= FLAG_SIGFIGS;
                break;
            case 's':
                new_vals[FLAG_SNAPLEN] = atoi(optarg);
                flags |= FLAG_SNAPLEN;
                break;
            case 'M':
                new_vals[FLAG_MAJOR_VERSION] = atoi(optarg);
                flags |= FLAG_MAJOR_VERSION;
                break;
            case 'm':
                new_vals[FLAG_MINOR_VERSION] = atoi(optarg);
                flags |= FLAG_MINOR_VERSION;
                break;
            case 'I':
                header_info = 1;
                break;
            case 'L':
                linktype_info = 1;
                break;

            default: //fallthru
                printf("unknown option %c\n", c);
            case 'h':
                
                usage(argv[0]);
                if (linktype_info) {
                    show_linktypes();
                }

                return 1;
            break;
        }
    }

    if (optind == argc) {
        usage(argv[0]);
        if (linktype_info) {
            show_linktypes();
        }
        return 1;
    }
    if (linktype_info) {
        show_linktypes();
    }

    if (!flags && !header_info) {
        puts("Nothing to change");
        usage(argv[0]);
        return 1;
    }

    while (optind < argc) {
        int fd;
        int other_endian;

        fd = open_pcap(argv[optind], &other_endian);
        if (fd >= 0) {

            if (header_info) {
                printf("pcap header for '%s'\n", argv[optind]);
                show_header(fd, other_endian);
            }

            if (flags) {
                change_header(fd, other_endian, flags, new_vals);
            }

            close(fd);
        }
        optind++;
    }

    return 0;
}
