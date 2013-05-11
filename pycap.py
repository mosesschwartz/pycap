# pycap.py

import struct



# Standard libpcap format.
TCPDUMP_MAGIC = 0xa1b2c3d4

# Alexey Kuznetzov's modified libpcap format.
KUZNETZOV_TCPDUMP_MAGIC = 0xa1b2cd34



'''
enum pcap1_info_types {
        PCAP_DATACAPTURE,
    PCAP_TIMESTAMP,
    PCAP_WALLTIME,
    PCAP_TIMESKEW,
    PCAP_PROBEPLACE,              /* aka direction */
    PCAP_COMMENT,                 /* comment */
};



struct pcap1_info_timestamp {
    struct pcap1_info_container pic;
    bpf_u_int32    nanoseconds;   /* 10^-9 of seconds */
    bpf_u_int32    seconds;       /* seconds since Unix epoch - GMT */
    bpf_u_int16    macroseconds;  /* 16 bits more of MSB of time */
    bpf_u_int16    sigfigs;       /* accuracy of timestamps - LSB bits */
};  
    
struct pcap1_info_packet {
    struct pcap1_info_container pic;
    bpf_u_int32 caplen; /* length of portion present */
    bpf_u_int32 len;    /* length this packet (off wire) */
    bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
    bpf_u_int32 ifIndex;    /* abstracted interface index */
    unsigned char packet_data[0];
};  

enum pcap1_probe {
    INBOUND  =1,
    OUTBOUND =2,
    FORWARD  =3,
    PREENCAP =4,
    POSTDECAP=5,
};

struct pcap1_info_probe {
    struct pcap1_info_container pic;
    bpf_u_int32                 probeloc;   /* enum pcap1_probe */
        unsigned char               probe_desc[0];
};
    
struct pcap1_info_comment {
    struct pcap1_info_container pic;
        unsigned char               comment[0];
};
'''  


'''
struct pcap_timeval {
    bpf_int32 tv_sec;       /* seconds */
    bpf_int32 tv_usec;      /* microseconds */
};
'''
pcap_timeval_fmt = "II"
pcap_timeval_fields = ['tv_sec', 'tv_usec']

'''
struct pcap_sf_pkthdr {
    struct pcap_timeval ts; /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;        /* length this packet (off wire) */
};
'''
pcap_sf_pkthdr_fmt = pcap_timeval_fmt + "II"
pcap_sf_pkthdr_fields = pcap_timeval_fields + ['caplen', 'len']

'''
struct pcap1_info_container {
    bpf_u_int32 info_len;         /* in bytes */
    bpf_u_int32 info_type;        /* enum pcap1_info_types */
    unsigned char info_data[0];
};
'''
pcap1_info_container_fmt = "IIB"
pcap1_info_container_fields = ['info_len', 'info_type', 'info_data']

'''
struct pcap1_packet_header {
    bpf_u_int32 magic;
    u_short     version_major;
    u_short     version_minor;
        bpf_u_int32 block_len;
    struct pcap1_info_container pics[0];
};
'''
pcap1_packet_header_fmt = "IHHI"
pcap1_packet_header_fields = ['magic', 'version_major', 'version_minor', 'block_len'] + pcap1_info_container_fields


f = open('http.cap','rb')

fmt = pcap1_packet_header_fmt+pcap1_info_container_fmt

header_size = struct.calcsize(fmt)
magic = f.read(header_size)

header = struct.unpack(fmt, magic)
print zip(pcap1_packet_header_fields, header)

packet = f.read(struct.calcsize(pcap_sf_pkthdr_fmt))
print zip(pcap_sf_pkthdr_fields, packet)













