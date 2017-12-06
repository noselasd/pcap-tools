AM_CPPFLAGS = $(all_includes) #-I$(top_srcdir)/include -I$(top_builddir)/
AM_CFLAGS = -Wall $(PCAP_CFLAGS)

bin_PROGRAMS = pcap-dump pcap-changehdr pcap-duplicate

pcap_dump_SOURCES = pcap-dump.c
pcap_dump_LDADD = $(PCAP_LIBS) 

pcap_changehdr_SOURCES = pcap-changehdr.c
pcap_changehdr_LDADD = $(PCAP_LIBS) 

pcap_duplicate_SOURCES = pcap-duplicate.c
pcap_duplicate_LDADD = $(PCAP_LIBS) 

