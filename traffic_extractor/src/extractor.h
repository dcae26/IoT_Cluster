//
//  extractor.h
//

#pragma once
#ifndef dumpTool_mac_h
#define dumpTool_mac_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <string>
#include <cmath>
#include <set>
#include <vector>
#include <unordered_map>

#include <fstream>
#include <sstream>

#include <dirent.h>

#include <net/ethernet.h>

#include <arpa/inet.h>

#include <pcap.h>

using namespace std;

#define SHOW_PACKETCOUNT true

#define NONIOTCLASS 24
#define PCAP_BUF_SIZE    2048

//Input
#define IOTLISTDIR "iotList.csv"
#define PTLISTDIR "ports.csv"
#define DMLISTDIR "domain.csv"
#define CSLISTDIR "cipher_suite.csv"

//Output
#define OUT_ORIGIN "raw_data.csv"
#define OUT_INFO "info.csv"
#define OUT_PTBAG "bag_ports.csv"
#define OUT_DMBAG "bag_domain.csv"
#define OUT_CSBAG "bag_cipher_suite.csv"
#define OUT_STAGE1 "stage1_vec.csv"
#define OUT_NWFEATURE "nw_feature.csv"
#define OUT_MINDIS "min_distribution.csv"

#define CLS_OTHER_STR "__Other__"
#define CLS_OTHER_NUM -1

//ML Dimention
#define RPN_DIM 2048
#define DM_DIM 123
#define CS_DIM 13

//Ethernet
#define SIZE_ETHERNET 14

//DNS
#define OFFSET_DNS_HEAD 12

//TLS packet parameters
#define TLS_CLIENT_HELLO    1
#define TLS_SERVER_HELLO    2
#define OFFSET_HELLO_VERSION    9
#define OFFSET_SESSION_LENGTH   43
#define SSL_MIN_GOOD_VERSION    0x002
#define SSL_MAX_GOOD_VERSION    0x304

//Hex Table
char hex_table[16] = {
    '0','1','2','3','4','5','6','7',
    '8','9','a','b','c','d','e','f'};

//MAC addr filter (Gateway)
set<string> mac_filter = {
    "14:cc:20:51:33:ea",//gateway TP-link
    "08:21:ef:3b:fc:e3",//gateway Samsung
    "14:cc:20:51:33:e9",//unknown gateway like device
    "ff:ff:ff:ff:ff:ff" //broadcast
};

set<string> mac_filter_head2 = {
    "33:33"
};

set<string> mac_filter_head3 = {
    "01:00:5e"
};

//IP header
struct pckIp {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define IP_FLAG_OFF 6
#define DF_H 64
#define DF_L 0

//TCP Header
//typedef u_int tcp_seq;
struct pckTcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    u_int th_seq;                   /* sequence number */
    u_int th_ack;                   /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};
#define TCP_OPT_OFF 20

//UDP
struct udphdr {
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* udp length */
    u_short uh_sum;                 /* udp checksum */
};

struct instance_stage_0 {
    u_int rpn[RPN_DIM];//bag of remote port number
    u_int dm[DM_DIM];//bag of domain names
    u_int cs[CS_DIM];//bag of cipher suites
};

struct instance_stage_1 {
    u_long flow_volume;
    double flow_rate;//KB/s
    
    u_long flow_duration;
    double sleep_time;
    u_int sleep_time_count;
    double dns_interval;
    u_int dns_interval_count;
    double ntp_interval;
    u_int ntp_interval_count;
};

class Instance {
public:
    string mac_adr;
    string flow_match;
    int device_class;
    
    bool train_flag;
    bool last_dns_set;
    bool last_ntp_set;
    
    timeval last_flow;
    timeval last_dns;
    timeval last_ntp;
    
    const u_long create_time;
    
    u_long df_flag_cnt;
    double avg_rwin;//h
    double avg_mss;//h
    u_long mss_cnt;
    double avg_sen;//h
    u_long sen_cnt;
    
    u_long tcp_cnt;
    u_long udp_cnt;
    u_long ip_cnt;
    u_long icmp_cnt;
    u_long http_cnt;
    u_long dhcp_cnt;
    
    set<string> destIp;
    u_long destIp_cnt;
    
    u_long min_pck_cnt_acc;
    u_long min_pck_cnt[59];
    
    instance_stage_0 stage0;
    instance_stage_1 stage1;
public:
    Instance(string sourceMAC,bool iotflag,timeval ct);
    void hour_end_calc();
};

//bag feature vector
vector<string> pt_vec;
vector<string> dm_vec;
vector<string> cs_vec;

//iot devices
//key:   MAC addr
//value: device type
unordered_map<string,int> iotMap;

//remote port
unordered_map<int,int> portMap;

//domain information
unordered_map<string,int> domainMap;

//cipher suite information
//key  : encoded cipher suite
//value: frequency
unordered_map<string,int> cipher_suite;

//instance
//key:   MAC addr
//value: < flag if need to insert new instance in this hour,
//         corresponding Instance list >
unordered_map<string,pair<bool,vector<Instance>>> h_instance;

//global parameters
bool hour_base_set;//flag of hour base
int min_index;

timeval hour_base;
timeval min_base;

u_int local_cnt=0;
long packet_count=0;
long long all_packet_count=0;
long long iot_count=0;
long long non_iot_count=0;

void print_banner() {
    cout<<"===========================================================\n"<<
    "#  _____   _______    _____ _               _             #\n"<<
    "# |_   _| |__   __|  / ____| |             | |            #\n"<<
    "#   | |  ___ | |    | |    | | __ _ ___ ___| |_ ___ _ __  #\n"<<
    "#   | | / _ \\| |    | |    | |/ _` / __/ __| __/ _ \\ '__| #\n"<<
    "#  _| || (_) | |    | |____| | (_| \\__ \\__ \\ ||  __/ |    #\n"<<
    "# |_____\\___/|_|     \\_____|_|\\__,_|___/___/\\__\\___|_|    #\n";
    cout<<"#                                                         #\n"<<
    "#                ---Traffic Extractor---                  #\n";
    cout<<"===========================================================\n\n";
}

//Function Declare
vector<string> getFilenames(string fdir, string strip);
void data_initialize(string iot,string port,string domain,string cps);
void resultSaving(string savdir);
void raw_saving(string data_dir);

void min_init();

string macConv(const u_char ether_shost[ETHER_ADDR_LEN]);
void nonIotPush(string MAC,timeval time);
u_long toUsec(timeval ts);
string arrayEncoding(u_int* array, int dimention);
double shannon_entropy(u_char* data,u_int len);

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
string encodingCipherSuite(const u_char *cipher_data);
void decodingCipherSuite();

string ssl_version(u_short version) {
    static char hex[7];
    switch (version) {
        case 0x002: return "SSLv2";
        case 0x300: return "SSLv3";
        case 0x301: return "TLSv1";
        case 0x302: return "TLSv1.1";
        case 0x303: return "TLSv1.2";
    }
    snprintf(hex, sizeof(hex), "0x%04hx", version);
    return hex;
}

#endif /* extractor_h */
