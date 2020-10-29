//
//  dataPreProcess.cpp
//

#include <iostream>
#include <unordered_map>
#include <set>
#include <vector>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <string.h>
#include <algorithm>

#include <dirent.h>

#include <netinet/in.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <pcap.h>

#define DIRSPLIT "/"
#define IOTLISTDIR "iotList.csv"
#define PTLISTDIR "ports.csv"
#define DMLISTDIR "domain.csv"
#define CSLISTDIR "cipher_suite.csv"

using namespace std;

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

//custom cmp
struct pair_cmp {
    bool operator() (const pair<string,u_int> &a, const pair<string,u_int> &b) {
        return a.second > b.second;
    }
};

struct pt_cmp {
    bool operator() (const pair<u_int,pair<u_int,u_int>> &a, const pair<u_int,pair<u_int,u_int>> &b) {
        return (a.second.first+a.second.second) > (b.second.first+b.second.second);
    }
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

//TCP Header
//typedef u_int tcp_seq;
struct pckTcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    //tcp_seq th_seq;                 /* sequence number */
    //tcp_seq th_ack;                 /* acknowledgement number */
    u_int th_seq;
    u_int th_ack;
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

//UDP
struct udphdr {
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* udp length */
    u_short uh_sum;                 /* udp checksum */
};

//iot devices
//key:   MAC addr
//value: device type
unordered_map<string,int> iotMap;

//value: TCP_cnt UDP_cnt
unordered_map<u_int,pair<u_int,u_int>> remote_port;
unordered_map<string,u_int> domain;
unordered_map<string,u_int> cipher_suite;

bool all_flag=false;
long packet_count=0;
long iot_count=0;
long non_iot_count=0;

//Hex Table
char hex_table[16] = {
    '0','1','2','3','4','5','6','7',
    '8','9','a','b','c','d','e','f'};

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

void print_banner() {
    cout<<"===========================================================\n"<<
    "#  _____   _______    _____ _               _             #\n"<<
    "# |_   _| |__   __|  / ____| |             | |            #\n"<<
    "#   | |  ___ | |    | |    | | __ _ ___ ___| |_ ___ _ __  #\n"<<
    "#   | | / _ \\| |    | |    | |/ _` / __/ __| __/ _ \\ '__| #\n"<<
    "#  _| || (_) | |    | |____| | (_| \\__ \\__ \\ ||  __/ |    #\n"<<
    "# |_____\\___/|_|     \\_____|_|\\__,_|___/___/\\__\\___|_|    #\n";
    cout<<"#                                                         #\n"<<
    "#              ---Pcap Data Preobservation---             #\n";
    cout<<"===========================================================\n\n";
}

string macConv(const u_char ether_shost[ETHER_ADDR_LEN]) {
    string res;
    for(int i=0;i<ETHER_ADDR_LEN;++i) {
        int tmp=ether_shost[i];
        res.push_back(hex_table[tmp/16]);
        res.push_back(hex_table[tmp%16]);
        res+=":";
    }
    res.pop_back();
    return res;
}

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

vector<string> getFilenames(const char* fdir, string strip) {
    /*
     fdir : read directory path
     strip: suffix filter
     */
    vector<string> res;
    DIR *dir;
    struct dirent *ent;
    if ((dir=opendir(fdir))!=NULL) {
        while ((ent=readdir(dir))!=NULL) {
            string tmp=ent->d_name;
            if(tmp.size()>(strip.size()+1)&&
               tmp.substr(tmp.size()-strip.size(),strip.size())==strip) {
                res.push_back(tmp);
            }
        }
        closedir (dir);
    }
    else {
        cout<<"Can't open directory.\n";
        exit(1);
    }
    return res;
}

int main(int argc, const char * argv[]) {
    if(argc<2) {
        cout<<"Arguments Fault. Expected 4.\n";
        cout<<"Usage:<program> <mode> <data_dir(pcap+iotList)> <out_dir>\n";
        cout<<"<mode>:a string, \"iot\" only observe IoT packet with provided list\n"<<
              "                 \"all\" observe all packet\n";
        exit(1);
    }
    string tmp=argv[1];
    if(tmp=="iot") {
        all_flag=false;
    }
    else if(tmp=="all") {
        all_flag=true;
    }
    else{
        cout<<"Mode name error!\n";
        cout<<"Usage:<program> <mode> [data_dir(pcap+iotList)] <out_dir>\n";
        cout<<"<mode>:a string, \"iot\" only observe IoT packet with provided list\n"<<
              "                 \"all\" observe all packet\n";
        exit(1);
    }
    tmp.clear();

    if(argc!=4) {
        cout<<"Arguments Fault. Expected 4.\n";
        cout<<"Usage:<program> <mode> <data_dir(pcap+iotList)> <out_dir>\n";
        cout<<"<mode>:a string, \"iot\" only observe IoT packet with provided list\n"<<
              "                 \"all\" observe all packet\n";
        exit(1);
    }

    tmp=argv[2];
    if(tmp.back()!='/') tmp.push_back('/');
    char* DATADIR=new char[sizeof(tmp)];
    strcpy(DATADIR,tmp.c_str());
    tmp.clear();

    tmp=argv[3];
    if(tmp.back()!='/') tmp.push_back('/');
    char* OUTDIR=new char[sizeof(tmp)];
    strcpy(OUTDIR,tmp.c_str());
    tmp.clear();

    print_banner();
    vector<string> data_files;

    if(!all_flag) {
        cout<<"Mode: IoT Packet\n";
        //Load iotList
        cout<<"Initializing iotMap...\n";
        ifstream inFile((string)DATADIR+(string)IOTLISTDIR,ios::in);
        if (inFile.fail()) {
            cout<<"File "<<(string)DATADIR+(string)IOTLISTDIR<<" open failed."<<endl;
            exit(1);
        }
        else {
            string line;
            while(getline(inFile, line)) {
                short tmp=line.rfind(',')+1;
                string mac=line.substr(line.find(',')+1,17);
                iotMap.insert(pair<string,int>(mac,atoi(line.substr(tmp,line.size()-tmp).c_str())));
            }
        }
        inFile.close();
        cout<<"Done.\n";
    }
    else {
        cout<<"Mode: All Packet\n";
        data_files = getFilenames(DATADIR,"csv");
        for(int i=0;i<data_files.size();++i) {
            if(data_files[i]==IOTLISTDIR) {
                cout<<"WARNING: This process will create a blank Device List to the output directory. "
                <<"We found you already have "<<IOTLISTDIR<<" there, the file will be overwrited to blank. "
                <<"Please confirm to go on the process y/[n]: ";
                char input;
                cin>>input;
                if(input!='y') {
                    cout<<"User abort.\n";
                    exit(0);
                }
            }
        }
    }

    data_files=getFilenames(DATADIR,"pcap");
    for(int i=0;i<data_files.size();++i) {
        cout<<"Processing "<<data_files[i]<<" ...\n";
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];

        fp = pcap_open_offline((string(DATADIR)+DIRSPLIT+data_files[i]).c_str(),errbuf);
        if (fp == NULL) {
            fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
            exit(1);
        }

        if (pcap_loop(fp,0,packetHandler,NULL) < 0) {
            fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
            exit(1);
        }

        cout<<endl;

        //cout<<"Max First:"<<max_first<<endl;
        //cout<<"Max Second:"<<max_second<<endl;
        cout<<"Done.\n";
    }

    //port saving
    ofstream out;
    cout<<"Saving to "<<(string)OUTDIR+(string)PTLISTDIR<<endl;
    out.open((string)OUTDIR+(string)PTLISTDIR);
    if(out.fail()) {
        cout<<"Output file "<<(string)OUTDIR+(string)PTLISTDIR<<" open failed."<<endl;
        exit(1);
    }
    //int sim_count=0;
    vector<pair<u_int,pair<u_int,u_int>>> pt_sav_vec;
    for(unordered_map<u_int,pair<u_int,u_int>>::iterator it=remote_port.begin();
         it!=remote_port.end(); ++it) {
//        if((*it).second.first!=(*it).second.first+(*it).second.second &&
//           (*it).second.second!=(*it).second.first+(*it).second.second) {
//            ++sim_count;
//        }
//        out<<(*it).first<<','<<(*it).second.first<<','<<(*it).second.second
//        <<','<<(*it).second.first+(*it).second.second<<endl;
        pt_sav_vec.push_back((*it));
    }
    sort(pt_sav_vec.begin(),pt_sav_vec.end(),pt_cmp());
    for(int i=0;i<pt_sav_vec.size();++i) {
        out<<pt_sav_vec[i].first<<','<<pt_sav_vec[i].second.first<<','
            <<pt_sav_vec[i].second.second<<','
            <<pt_sav_vec[i].second.first+pt_sav_vec[i].second.second<<endl;
    }
    pt_sav_vec.clear();
    out.close();
    //cout<<"UnSimilar count: "<<sim_count<<endl;
    cout<<"Success.\n";

    //domain saving
    cout<<"Saving to "<<(string)OUTDIR+(string)DMLISTDIR<<endl;
    out.open((string)OUTDIR+(string)DMLISTDIR);
    if(out.fail()) {
        cout<<"Output file "<<(string)OUTDIR+(string)DMLISTDIR<<" open failed."<<endl;
        exit(1);
    }
    //int sim_count=0;
    vector<pair<string,u_int>> dm_sav_vec;
    for(unordered_map<string,u_int>::iterator it=domain.begin();it!=domain.end(); ++it) {
        //out<<(*it).first<<','<<(*it).second<<endl;
        dm_sav_vec.push_back((*it));
    }
    sort(dm_sav_vec.begin(),dm_sav_vec.end(),pair_cmp());
    for(int i=0;i<dm_sav_vec.size();++i) {
        out<<dm_sav_vec[i].first<<','<<dm_sav_vec[i].second<<endl;
    }
    dm_sav_vec.clear();
    out.close();
    cout<<"Success.\n";

    //cipher suite saving
    cout<<"Saving to "<<(string)OUTDIR+(string)CSLISTDIR<<endl;
    out.open((string)OUTDIR+(string)CSLISTDIR);
    if(out.fail()) {
        cout<<"Output file "<<(string)OUTDIR+(string)CSLISTDIR<<" open failed."<<endl;
        exit(1);
    }
    vector<pair<string,u_int>> cs_sav_vec;
    string tmp_cs;
    for(unordered_map<string,u_int>::iterator it=cipher_suite.begin();
        it!=cipher_suite.end();++it) {
//        out<<"[";
//        for(int i=0;i<(*it).first.size()-4;++i) {
//            out<<(*it).first[i];
//            out<<(*it).first[++i];
//            out<<(*it).first[++i];
//            out<<(*it).first[++i];
//            out<<":";
//        }
//        out<<(*it).first[(*it).first.size()-4]<<(*it).first[(*it).first.size()-3]<<\
//        (*it).first[(*it).first.size()-2]<<(*it).first[(*it).first.size()-1];
//        //        out<<hex<<setw(2)<<setfill('0')<<(u_short)(*it).first[(*it).first.size()-2];
//        //        out<<hex<<setw(2)<<setfill('0')<<(u_short)(*it).first[(*it).first.size()-1];
//        out<<"],";
//        out<<(*it).second<<endl;
        tmp_cs+='[';
        for(int i=0;i<(*it).first.size()-4;++i) {
            tmp_cs+=(*it).first[i];
            tmp_cs+=(*it).first[++i];
            tmp_cs+=(*it).first[++i];
            tmp_cs+=(*it).first[++i];
            tmp_cs+=":";
        }
        tmp_cs+=(*it).first[(*it).first.size()-4];
        tmp_cs+=(*it).first[(*it).first.size()-3];
        tmp_cs+=(*it).first[(*it).first.size()-2];
        tmp_cs+=(*it).first[(*it).first.size()-1];
        tmp_cs+=']';
        cs_sav_vec.push_back(pair<string,u_int>(tmp_cs,(*it).second));
        tmp_cs.clear();
    }
    sort(cs_sav_vec.begin(),cs_sav_vec.end(),pair_cmp());
    for(int i=0;i<cs_sav_vec.size();++i) {
        out<<cs_sav_vec[i].first<<','<<cs_sav_vec[i].second<<endl;
    }
    cs_sav_vec.clear();
    out.close();
    cout<<"Success.\n";

    //create a blank iot list
    if(all_flag) {
        cout<<"Creating a blank iot list in "<<(string)OUTDIR+(string)IOTLISTDIR<<endl;
        out.open((string)OUTDIR+(string)IOTLISTDIR);
        if (out.fail()) {
            cout<<"Output file "<<(string)OUTDIR+(string)IOTLISTDIR<<" open failed."<<endl;
            exit(1);
        }
        out.close();
        cout<<"Success.\n";
    }

    cout<<"Port Nums:"<<remote_port.size()<<endl;
    cout<<"Domain Nums:"<<domain.size()<<endl;
    cout<<"Cipher Suite Nums:"<<cipher_suite.size()<<endl;
    cout<<"Packet Count:"<<packet_count<<endl;
    if(!all_flag) {
        cout<<"IoT Count:"<<iot_count<<endl;
        cout<<"Non-IoT Count:"<<non_iot_count<<endl;
    }

    return 0;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    cout<<"\rPacket Processed:"<<packet_count;
    ++packet_count;

    const struct ether_header* ethernetHeader;
    const struct pckIp* ipHeader;
    const struct pckTcp* tcpHeader;
    const struct udphdr* udpHeader;
    u_int sourcePort, destPort;
    u_char *data;
    int dataLength = 0;
    int size_ip = 0;
    int size_tcp = 0;

    ethernetHeader=(struct ether_header*)packet;

    if(!all_flag) {
        //Only process on when is the known Device Type
        if(iotMap.count(macConv(ethernetHeader->ether_shost))==0) {
            ++non_iot_count;
            return;
        }
        ++iot_count;
    }

    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {

        ipHeader = (struct pckIp*)(packet + sizeof(struct ether_header));
        size_ip = IP_HL(ipHeader)*4;

        //TCP
        if (ipHeader->ip_p == IPPROTO_TCP) {
            tcpHeader = (struct pckTcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcpHeader)*4;
            sourcePort = ntohs(tcpHeader->th_sport);
            destPort = ntohs(tcpHeader->th_dport);

            //remote port
            if(remote_port.count(destPort)==0) { //new port
                remote_port.insert(pair<u_int,pair<u_int,u_int>>(destPort,pair<u_int,u_int>(1,0)));
            }
            else { //found port
                ++remote_port[destPort].first;
            }

            data = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            dataLength = ntohs(ipHeader->ip_len) - (size_ip + size_tcp);

            //TLS Client Hello
            if(destPort==443 && data[0]==0x16 && data[5]==0x01) {

                u_short proto_version = data[1]*256 + data[2];
                //cout<<ssl_version(proto_version)<<" ";
                u_short hello_version = data[OFFSET_HELLO_VERSION]*256 + data[OFFSET_HELLO_VERSION+1];

                if (proto_version < SSL_MIN_GOOD_VERSION || proto_version >= SSL_MAX_GOOD_VERSION ||
                    hello_version < SSL_MIN_GOOD_VERSION || hello_version >= SSL_MAX_GOOD_VERSION) {
                    cout<<ssl_version(hello_version)<<" bad version(s)\n";
                    return;
                }

                // skip session ID
                const u_char *cipher_data = &data[OFFSET_SESSION_LENGTH];
                if (dataLength < OFFSET_SESSION_LENGTH + cipher_data[0] + 3) {
                    printf("SessionID too long: %hhu bytes\n", cipher_data[0]);
                    return;
                }

                cipher_data += 1 + cipher_data[0];

                //cout<<"ClientHello "<<ssl_version(hello_version)<<endl;

                u_short cs_len = cipher_data[0]*256 + cipher_data[1];
                cipher_data += 2; // skip cipher suites length

                set<pair<u_short,u_short>> csTmp;
                int cs_id;
                for (cs_id = 0; cs_id < cs_len/2; cs_id++) {
                    //                    printf("%02hhX%02hhX-->", cipher_data[2*cs_id], cipher_data[2*cs_id + 1]);
                    //                    cout<<(short)cipher_data[2*cs_id]*256+cipher_data[2*cs_id + 1]<<endl;
                    csTmp.insert(pair<u_short,u_short>(cipher_data[2*cs_id],cipher_data[2*cs_id + 1]));
                }

                string strTmp;
                for (set<pair<u_short,u_short>>::iterator p = csTmp.begin(); p != csTmp.end(); ++p) {
                    if((*p).first<16) {
                        strTmp.push_back('0');
                        strTmp+=hex_table[(*p).first];
                    }
                    else {
                        strTmp+=hex_table[(int)(*p).first/16];
                        strTmp+=hex_table[(*p).first%16];
                    }

                    if((*p).second<16) {
                        strTmp.push_back('0');
                        strTmp+=hex_table[(*p).second];
                    }
                    else {
                        strTmp+=hex_table[(int)(*p).second/16];
                        strTmp+=hex_table[(*p).second%16];
                    }
                    //cout<<(*p).first<<" "<<(*p).second<<endl;
                }
                //                cout<<endl;
                //                cout<<csTmp.size()<<endl;
                //                cout<<strTmp.size()<<endl;
                //                cout<<strTmp<<endl;
                //                exit(1);

                if(cipher_suite.count(strTmp)==0) {//not exist
                    cipher_suite.insert(pair<string,u_int>(strTmp,1));
                }
                else {//found
                    ++cipher_suite[strTmp];
                }

            }
        }

        //UDP
        if (ipHeader->ip_p == IPPROTO_UDP) {
            //++udpCount;
            u_int sourcePort, destPort;
            u_char *data;

            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct pckIp));
            sourcePort = ntohs(udpHeader->uh_sport);
            destPort = ntohs(udpHeader->uh_dport);

            if(remote_port.count(destPort)==0) { //new port
                remote_port.insert(pair<u_int,pair<u_int,u_int>>(destPort,pair<u_int,u_int>(0,1)));
            }
            else { //found port
                ++remote_port[destPort].second;
            }

            //DNS
            if(sourcePort==53 || destPort==53) {
                data = (u_char*)(packet + SIZE_ETHERNET + size_ip + sizeof(struct udphdr) + OFFSET_DNS_HEAD);
                int count=data[0];
                int index=0;
                string dmTmp;
                while(data[index]!=0) {
                    count=data[index];
                    ++index;
                    while(count!=0) {
                        dmTmp.push_back(data[index]);
                        ++index;
                        --count;
                    }
                    dmTmp.push_back('.');
                }
                if(!dmTmp.empty()) dmTmp.pop_back();
                //                cout<<"\ndmTmp:"<<dmTmp<<endl;
                //                cout<<dmTmp.size()<<endl;
                //                exit(1);
                if(domain.count(dmTmp)==0) { //new domain
                    domain.insert(pair<string,u_int>(dmTmp,1));
                }
                else { //found domain
                    ++domain[dmTmp];
                }
            }

        }
    }
}
