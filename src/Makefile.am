AM_CPPFLAGS = $(all_includes) #-I$(top_srcdir)/include -I$(top_builddir)/
AM_CFLAGS = -Wall $(PCAP_CFLAGS)

bin_PROGRAMS = pcap-info pcap-changehdr

pcap_info_SOURCES = pcap-info.c
pcap_info_LDADD = $(PCAP_LIBS) 

pcap_changehdr_SOURCES = pcap-changehdr.c
pcap_changehdr_LDADD = $(PCAP_LIBS) 

