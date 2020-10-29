//
//  extractor.cpp
//

#include "extractor.h"

vector<string> getFilenames(string ddir, string strip) {
    /*
     fdir : read directory path
     strip: suffix filter
    */
    vector<string> res;
    const char* fdir=ddir.c_str();
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

u_long toUsec(timeval ts) {
    return ts.tv_sec*1000000+ts.tv_usec;
}

void data_initialize(string iot,string port,string domain,string cps) {
    //Load IoT Device List
    cout<<"Initializing iotMap...\n";
    ifstream inFile(iot,ios::in);
    if (inFile.fail()) {
        cout<<"File "<<iot<<" open failed."<<endl;
        exit(1);
    }
    else {
        string line;
        while(getline(inFile, line)) {
            short tmp=line.rfind(',')+1;
            string mac=line.substr(line.find(',')+1,17);
            iotMap.insert(pair<string,int>(mac,atoi(line.substr(tmp,line.size()-tmp).c_str())));
            h_instance.insert(pair<string,pair<bool,vector<Instance>>>
                              (mac,pair<bool,vector<Instance>>(true,vector<Instance>())));
        }
    }
    inFile.close();
    cout<<"Done.\n";
//    for(unordered_map<string,int>::iterator it=iotMap.begin();it!=iotMap.end();++it) {
//        cout<<(*it).first<<"\t"<<(*it).second<<endl;
//    }
//    cout<<"IoT List Size:"<<iotMap.size()<<endl;
//    exit(1);

    int index=0;

    //Load Port map
    cout<<"Initializing portMap...\n";
    inFile.open(port,ios::in);
    if (inFile.fail()) {
        cout<<"File "<<port<<" open failed."<<endl;
        exit(1);
    }
    else {
        string line;
        for(int i=0;i<RPN_DIM-1;++i) {
            getline(inFile, line);
            string pt=line.substr(0,line.find(','));
            portMap.insert(pair<int,int>(stoi(pt),index++));
            pt_vec.push_back(pt);
        }
        portMap.insert(pair<int,int>(CLS_OTHER_NUM,index));
        pt_vec.push_back(CLS_OTHER_STR);
    }
    cout<<"Done.\n";
    inFile.close();

    index=0;
//    for(unordered_map<int, int>::iterator it=portMap.begin();it!=portMap.end();++it) {
//        cout<<(*it).first<<"\t"<<(*it).second<<endl;
//    }

    //Load Domain
    cout<<"Initializing domainMap...\n";
    inFile.open(domain,ios::in);
    if (inFile.fail()) {
        cout<<"File "<<domain<<" open failed."<<endl;
        exit(1);
    }
    else {
        string line;
        for(int i=0;i<DM_DIM-1;++i) {
            getline(inFile, line);
            string dm=line.substr(0,line.find(','));
            domainMap.insert(pair<string,int>(dm,index++));
            dm_vec.push_back(dm);
        }
        domainMap.insert(pair<string,int>(CLS_OTHER_STR,index));
        dm_vec.push_back(CLS_OTHER_STR);
    }
    cout<<"Done.\n";
    inFile.close();

    index=0;

    //Load Cipher Suite
    cout<<"Initializing cipher suite...\n";
    inFile.open(cps,ios::in);
    if (inFile.fail()) {
        cout<<"File "<<cps<<" open failed."<<endl;
        exit(1);
    }
    else {
        string line;
        string tmpLine;
        for(int i=0;i<CS_DIM-1;++i) {
            getline(inFile, line);
            line=line.substr(0,line.find(','));
            tmpLine.clear();
            for(int j=1;j<line.size()-1;++j) {
                if(line[j]!=':')
                    tmpLine.push_back(line[j]);
            }
            cipher_suite.insert(pair<string,int>(tmpLine,index++));
            cs_vec.push_back(line);
        }
        cipher_suite.insert(pair<string,int>(CLS_OTHER_STR,index));
        cs_vec.push_back(CLS_OTHER_STR);
    }
    cout<<"Initialize Done.\n\n";
    inFile.close();

//    for(unordered_map<string,int>::iterator it=cipher_suite.begin();it!=cipher_suite.end();++it) {
//        cout<<(*it).first<<"\t"<<(*it).second<<endl;
//    }
//    cout<<"Cipher Suite Size:"<<cipher_suite.size()<<endl;
//    exit(1);

}

Instance::Instance(string sourceMAC,bool iotflag,timeval ct):create_time(toUsec(ct)) {
    mac_adr=sourceMAC;

    iotflag?device_class=iotMap[sourceMAC]:device_class=NONIOTCLASS;

    train_flag=true;//initialize true

    //flag to deal with first packet
    last_dns_set=false;
    last_ntp_set=false;

    df_flag_cnt=0;
    avg_rwin=0;
    avg_mss=0;
    mss_cnt=0;
    avg_sen=0;
    sen_cnt=0;

    //arp_cnt=0;
    tcp_cnt=0;
    udp_cnt=0;
    ip_cnt=0;
    icmp_cnt=0;
    http_cnt=0;
    dhcp_cnt=0;

    //initialize bag features
    memset(stage0.rpn,0,sizeof(stage0.rpn));
    memset(stage0.dm,0,sizeof(stage0.dm));
    memset(stage0.cs,0,sizeof(stage0.cs));

    stage1.flow_volume=0;
    stage1.flow_rate=0;

    stage1.flow_duration=0;
    stage1.sleep_time=0;
    stage1.sleep_time_count=0;

    stage1.dns_interval=0;
    stage1.dns_interval_count=0;
    stage1.ntp_interval=0;
    stage1.ntp_interval_count=0;

    last_flow=ct;
    last_dns.tv_sec=0;
    last_ntp.tv_sec=0;

    destIp_cnt=0;

    memset(min_pck_cnt,0,sizeof(min_pck_cnt));
    min_pck_cnt_acc=0;
}

void Instance::hour_end_calc() {
    /*
     In order to enhance the efficiency of the extractor, some calculation remain undone and only
     calculate when the hour ends. These calculations are done hourly (timestamp).
    */

    destIp_cnt=destIp.size();
    destIp.clear();

    if(toUsec(last_flow)==create_time) {
        stage1.flow_duration=0;
        stage1.flow_rate=((double)stage1.flow_volume/1024)/(3600);//KB/s
    }
    else {
        //cout<<"--in2--\n";
        stage1.flow_duration=toUsec(last_flow)-create_time;
        stage1.flow_rate=((double)stage1.flow_volume/1024)/((double)stage1.flow_duration/1000000);//KB/s
    }

    if(stage1.dns_interval_count==0) stage1.dns_interval=0;
    else stage1.dns_interval=(double)stage1.dns_interval/stage1.dns_interval_count;

    if(stage1.ntp_interval_count==0) stage1.ntp_interval=0;
    else stage1.ntp_interval=(double)stage1.ntp_interval/stage1.ntp_interval_count;

    //sleep time here is the packet number in one hour
    if(stage1.sleep_time_count==1) {
        stage1.sleep_time=0;
    }
    else {
        stage1.sleep_time=(double)stage1.sleep_time/(stage1.sleep_time_count-1);
        avg_rwin=(double)avg_rwin/(stage1.sleep_time_count-1);
    }

    if(mss_cnt!=0) avg_mss=(double)avg_mss/mss_cnt;
    if(sen_cnt!=0) avg_sen=(double)avg_sen/sen_cnt;
}

void min_init() {
    min_base.tv_sec=0;
    min_base.tv_usec=0;
    min_index=0;
}

int main(int argc, char **argv) {
    if(argc != 3) {
        printf("Arguments Fault!\n");
        printf("Usage:<program> <data dir> <result dir>\n");
        printf("Data Dir should include:\n");
        printf("iotList.csv  ports.csv  domain.csv  cipher_suite.csv\n");
        return -1;
    }

    print_banner();

    string data_dir=argv[1];
    if(data_dir.back()!='/') {
        data_dir.push_back('/');
    }

    data_initialize(data_dir+(string)IOTLISTDIR,data_dir+(string)PTLISTDIR
                    ,data_dir+(string)DMLISTDIR,data_dir+(string)CSLISTDIR);

    vector<string> dataDir=getFilenames(data_dir,"pcap");
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];

    for(int i=0;i<dataDir.size();++i) {
        //new pcap file need to initilize parameters
        packet_count=0;
        hour_base_set=false;
        min_init();

        cout<<"Processing "<<dataDir[i]<<" ...\n";
        //cout<<(data_dir+dataDir[i]).c_str()<<endl;

        fp = pcap_open_offline((data_dir+dataDir[i]).c_str(), errbuf);

        if (fp == NULL) {
            fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
            exit(1);
        }

        if (pcap_loop(fp,0,packetHandler,NULL) < 0) {
            fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
            exit(1);
        }

        //Last hour of a day (pcap file)
        for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
            it!=h_instance.end();++it) {
            if(!(*it).second.second.empty()&&!(*it).second.first) (*it).second.second.back().hour_end_calc();
        }

        cout<<"\nPcap File Process Done.\n";

    }

    data_dir=argv[2];
    if(data_dir.back()!='/') {
        data_dir.push_back('/');
    }

    raw_saving(data_dir);
    resultSaving(data_dir);

    u_long ins_num=0;
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        ins_num+=(*it).second.second.size();
    }

    cout<<"\nTotal Packet Count:"<<all_packet_count<<endl;
    cout<<"Total IoT Count:"<<iot_count<<endl;
    cout<<"Total Non IoT Count:"<<non_iot_count<<endl;
    cout<<"Device Num:"<<h_instance.size()<<endl;
    cout<<"Instance Num:"<<ins_num<<endl;
    //cout<<"Size:"<<nh_instance.size()<<endl;

//    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
//        it!=h_instance.end();++it) {
//        cout<<"----------------------------\n";
//        cout<<"Mac addr:"<<(*it).first<<endl;
//        cout<<"Instance Num:"<<(*it).second.second.size()<<endl;
//    }
//    cout<<"----------------------------\n";

    //printf("\nProtocol Summary: %d ICMP packets, %d TCP packets, %d UDP packets\n", icmpCount, tcpCount, udpCount);
    //printf("DNS Summary: %d packets.\n", dnsCount);
    return 0;

}

void nonIotPush(string MAC,timeval time) {
    if(h_instance.count(MAC)==0) { //new device
        //cout<<"__New Non IoT Device__\n";
        h_instance.insert(pair<string,pair<bool,vector<Instance>>>
                          (MAC,pair<bool,vector<Instance>>(false,vector<Instance>())));
        h_instance[MAC].second.push_back(Instance(MAC,false,time));
    }
    else {
        if(h_instance[MAC].first) { //push instance
            //cout<<"__N Instance push__\n";
            h_instance[MAC].second.push_back(Instance(MAC,false,time));
            h_instance[MAC].first=false;
        }
    }
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    //unordered_map<string,pair<bool,vector<instance>>> h_instance;
#if SHOW_PACKETCOUNT
    cout<<"\rPacket Processed:"<<packet_count;
    ++packet_count;
#endif
    ++all_packet_count;

    //cout<<toUsec(pkthdr->ts)<<"-"<<toUsec(hour_base)<<"="<<(toUsec(pkthdr->ts))-(toUsec(hour_base))<<endl;

    //Divide by hour
    if(!hour_base_set) { //first packet
        hour_base_set=true;
        hour_base=pkthdr->ts;

//        cout<<"\nSec:"<<hour_base.tv_sec<<endl;
//        cout<<"uSec:"<<hour_base.tv_usec<<endl;
//        cout<<"Convert:"<<toUsec(hour_base)<<endl;

        //set all "insert flag" to true
        for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
            it!=h_instance.end();++it) {
            (*it).second.first=true;
        }

    }
    else if((toUsec(pkthdr->ts))-(toUsec(hour_base))>(u_long)3600000000) {
        //cout<<"\none hour:"<<all_packet_count<<endl;
        hour_base=pkthdr->ts;
        min_init();

        //set all "insert flag" to true
        for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
            it!=h_instance.end();++it) {
            if(!(*it).second.second.empty()&&!(*it).second.first) (*it).second.second.back().hour_end_calc();
            (*it).second.first=true;
        }

    }

    //minute packet
    if(min_base.tv_sec==0&&min_base.tv_usec==0) {
        min_base=pkthdr->ts;
    }
    else if((toUsec(pkthdr->ts)-(toUsec(min_base)))>(u_long)60000000) {
        min_base=pkthdr->ts;
        u_long tmp_cnt;
        for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
            it!=h_instance.end();++it) {
            if(!(*it).second.second.empty()) {
                tmp_cnt=(*it).second.second.back().stage1.sleep_time_count-(*it).second.second.back().min_pck_cnt_acc;
                (*it).second.second.back().min_pck_cnt_acc=(*it).second.second.back().stage1.sleep_time_count;
                (*it).second.second.back().min_pck_cnt[min_index]=tmp_cnt;
            }
        }
        ++min_index;
    }

    const struct ether_header* ethernetHeader;
    const struct udphdr* udpHeader;
    const struct pckIp* ipHeader;
    const struct pckTcp* tcpHeader;
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    u_int sourcePort;
    u_int destPort;
    u_char *data;
    u_int dataLength = 0;

    int size_ip = 0;
    int size_tcp = 0;

    double sen = 0;//shannon entropy

    string sourceMAC,destMAC;

    ethernetHeader=(struct ether_header*)packet;
    sourceMAC=macConv(ethernetHeader->ether_shost);
    destMAC=macConv(ethernetHeader->ether_dhost);

    //push flag
    //non-iot
    if(iotMap.count(sourceMAC)==0) {
        //Non-IoT device should filter out some MAC addr
        if(mac_filter.count(sourceMAC)!=0||mac_filter_head2.count(sourceMAC.substr(0,5))!=0||
           mac_filter_head3.count(sourceMAC.substr(0,8))!=0) return;
        nonIotPush(sourceMAC,pkthdr->ts);
        ++non_iot_count;
    }
    //iot
    else if(h_instance[sourceMAC].first) {
        ++iot_count;
        h_instance[sourceMAC].second.push_back(Instance(sourceMAC,true,pkthdr->ts));
        h_instance[sourceMAC].first=false;
    }
    else ++iot_count;

    //download volume，destMAC's sleep time、last flow
    if(iotMap.count(destMAC)==0) {
        //Non-IoT device should filter out some MAC addr
        if(mac_filter.count(destMAC)==0&&mac_filter_head2.count(destMAC.substr(0,5))==0&&
           mac_filter_head3.count(destMAC.substr(0,8))==0) {
            nonIotPush(destMAC,pkthdr->ts);
            h_instance[destMAC].second.back().stage1.flow_volume+=pkthdr->len;
            u_long last_flow=toUsec(h_instance[destMAC].second.back().last_flow);
            h_instance[destMAC].second.back().stage1.sleep_time+=toUsec(pkthdr->ts)-last_flow;
            ++h_instance[destMAC].second.back().stage1.sleep_time_count;
            h_instance[destMAC].second.back().last_flow=pkthdr->ts;
        }
    }
    else {
        h_instance[destMAC].second.back().stage1.flow_volume+=pkthdr->len;
        u_long last_flow=toUsec(h_instance[destMAC].second.back().last_flow);
        h_instance[destMAC].second.back().stage1.sleep_time+=toUsec(pkthdr->ts)-last_flow;
        ++h_instance[destMAC].second.back().stage1.sleep_time_count;
        h_instance[destMAC].second.back().last_flow=pkthdr->ts;
    }

    //upload volume, sleep time, last_flow
    h_instance[sourceMAC].second.back().stage1.flow_volume+=pkthdr->len;
    u_long last_flow=toUsec(h_instance[sourceMAC].second.back().last_flow);
    h_instance[sourceMAC].second.back().stage1.sleep_time+=toUsec(pkthdr->ts)-last_flow;
    ++h_instance[sourceMAC].second.back().stage1.sleep_time_count;
    h_instance[sourceMAC].second.back().last_flow=pkthdr->ts;

    //IP protocal
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ++h_instance[sourceMAC].second.back().ip_cnt;

        ipHeader = (struct pckIp*)(packet + sizeof(struct ether_header));
        size_ip = IP_HL(ipHeader)*4;
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);

        //dest ip count
        h_instance[sourceMAC].second.back().destIp.insert(destIP);

        //DF flag count
        data = (u_char*)(packet + SIZE_ETHERNET + IP_FLAG_OFF);
        if(data[0]==DF_H&&data[1]==DF_L) {
            ++h_instance[sourceMAC].second.back().df_flag_cnt;
        }

        //TCP
        if (ipHeader->ip_p == IPPROTO_TCP) {
            ++h_instance[sourceMAC].second.back().tcp_cnt;

            //tcpCount = tcpCount + 1;
            tcpHeader = (struct pckTcp*)(packet + SIZE_ETHERNET + size_ip);
            size_tcp = TH_OFF(tcpHeader)*4;
            sourcePort = ntohs(tcpHeader->th_sport);
            destPort = ntohs(tcpHeader->th_dport);

            //Receiver Window (WIN)
            h_instance[sourceMAC].second.back().avg_rwin += tcpHeader->th_win;

            //Max Segment Size (MSS)
            data = (u_char*)(packet + SIZE_ETHERNET + size_ip + TCP_OPT_OFF);//TCP head opt
            if(data[0]==0x02) { //kind=2 MMS field
//                cout<<endl<<sourceIP<<" "<<destIP<<endl;
//                if((local_cnt++)==9) exit(1);
//                u_int mss=0;
//                for(u_int i=(u_int)data[1]-2;i>0;--i) {
//                    mss+=(((u_int)data[data[1]-i])*pow(256,i-1));
//                }

                ++h_instance[sourceMAC].second.back().mss_cnt;
                h_instance[sourceMAC].second.back().avg_mss += (u_int)data[2]*16*16+(u_int)data[3];
            }

            //TCP payload
            data = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
            dataLength = ntohs(ipHeader->ip_len) - (size_ip + size_tcp);

            //Shannon Entropy
            sen = shannon_entropy(data, dataLength);
            if(sen!=0) {
                ++h_instance[sourceMAC].second.back().sen_cnt;
                h_instance[sourceMAC].second.back().avg_sen += sen;
            }

            //Port
            if(portMap.count(destPort)==0) { //Other port
                //cout<<"[WARNING] __IoT Other Remote Port__\n";
                ++h_instance[sourceMAC].second.back().stage0.rpn[RPN_DIM-1];
            }
            else {
                ++h_instance[sourceMAC].second.back().stage0.rpn[portMap[destPort]];
            }

            //HTTP
            if(destPort==80 || sourcePort==80) {
                ++h_instance[sourceMAC].second.back().http_cnt;
            }

            //TLS Client Hello
            if(destPort==443 && data[0]==0x16 && data[5]==0x01) {

                u_short proto_version = data[1]*256 + data[2];
                //cout<<ssl_version(proto_version)<<" ";
                u_short hello_version = data[OFFSET_HELLO_VERSION]*256 + data[OFFSET_HELLO_VERSION+1];

//                cout<<"[data]"<<endl;
//                for(int i=0;i<dataLength;++i) {
//                    printf("%04x:",data[i]);
//                }
//                cout<<"\n\n[TLS]\n";
//                for(int i=0;i<dataLength-data[12]/16*4;++i) {
//                    printf("%04x:",tlsPayload[i]);
//                }
//                printf("\nProto_version:%04x\n",proto_version);
//                printf("Hello_version:%04x\n",hello_version);

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

                //analyze cipher suite
                string current_cs=encodingCipherSuite(cipher_data);
                if(cipher_suite.count(current_cs)==0) { //Other
                    //cout<<"[WARNING] __IoT Other CS__\n";
                    ++h_instance[sourceMAC].second.back().stage0.cs[CS_DIM-1];
                }
                else {
                    //cout<<"__Match CS__\n";
                    ++h_instance[sourceMAC].second.back().stage0.cs[cipher_suite[current_cs]];
                }
            }//if client hello
        }//if tcp

        //UDP
        else if (ipHeader->ip_p == IPPROTO_UDP) {
            ++h_instance[sourceMAC].second.back().udp_cnt;

            //cout<<"UDP\n";
            //++udpCount;
            udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct pckIp));
            sourcePort = ntohs(udpHeader->uh_sport);
            destPort = ntohs(udpHeader->uh_dport);

            //Port
            if(portMap.count(destPort)==0) { //Other port
                //cout<<"[WARNING] __IoT Other Remote Port__\n";
                ++h_instance[sourceMAC].second.back().stage0.rpn[RPN_DIM-1];
            }
            else {
                ++h_instance[sourceMAC].second.back().stage0.rpn[portMap[destPort]];
            }

            //DNS
            if(sourcePort==53 || destPort==53) {
                //cout<<"DNS\n";

                //domain name analysis
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
                if(domainMap.count(dmTmp)==0) { //Other
                    //cout<<"[WARNING] __IoT Other Domain__\n";
                    ++h_instance[sourceMAC].second.back().stage0.dm[DM_DIM-1];
                }
                else {
                    //cout<<"__Match__\n";
                    ++h_instance[sourceMAC].second.back().stage0.dm[domainMap[dmTmp]];
                }

                //DNS interval
                //first pakcet
                if(!h_instance[sourceMAC].second.back().last_dns_set) {
                    h_instance[sourceMAC].second.back().last_dns=pkthdr->ts;
                    h_instance[sourceMAC].second.back().last_dns_set=true;
                }
                else {
                    u_long last_dns;
                    last_dns=toUsec(h_instance[sourceMAC].second.back().last_dns);
                    h_instance[sourceMAC].second.back().stage1.dns_interval +=
                        toUsec(pkthdr->ts)-last_dns;
                    ++h_instance[sourceMAC].second.back().stage1.dns_interval_count;
                    h_instance[sourceMAC].second.back().last_dns=pkthdr->ts;
                }

            }//if DNS

            //NTP
            else if(sourcePort==123 || destPort==123) {
                //first packet
                if(!h_instance[sourceMAC].second.back().last_ntp_set) {
                    h_instance[sourceMAC].second.back().last_ntp=pkthdr->ts;
                    h_instance[sourceMAC].second.back().last_ntp_set=true;
                }
                else {
                    u_long last_ntp;
                    last_ntp=toUsec(h_instance[sourceMAC].second.back().last_ntp);
                    h_instance[sourceMAC].second.back().stage1.ntp_interval +=
                        toUsec(pkthdr->ts)-last_ntp;
                    ++h_instance[sourceMAC].second.back().stage1.ntp_interval_count;
                    h_instance[sourceMAC].second.back().last_ntp=pkthdr->ts;
                }
            }//if NTP

            //DHCP
            else if(sourcePort==68 && destPort==67) {
                ++h_instance[sourceMAC].second.back().dhcp_cnt;
            }
        }//if UDP

        //ICMP
        else if(ipHeader->ip_p == IPPROTO_ICMP) {
            ++h_instance[sourceMAC].second.back().icmp_cnt;
        }
    }//if IP protocal
    //ARP Protocal
//    else if(ntohs(ethernetHeader->ether_type) == ETHERTYPE_ARP) {
//        ++h_instance[sourceMAC].second.back().arp_cnt;
//    }
}

string encodingCipherSuite(const u_char *cipher_data) {

    cipher_data += 1 + cipher_data[0];

    //++globalcount;
    //cout<<"ClientHello "<<ssl_version(hello_version)<<" ";

    u_short cs_len = cipher_data[0]*256 + cipher_data[1];
    cipher_data += 2; // skip cipher suites length

    set<pair<u_short,u_short>> csTmp;
    int cs_id;
    for (cs_id = 0; cs_id < cs_len/2; cs_id++) {
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

    return strTmp;
}

double shannon_entropy(u_char* data,u_int len) {
    if(len==0) return 0;

    double res=0;
    double p=0;
    vector<u_int> cnt(256,0);

    for(int i=0;i<len;++i) ++cnt[data[i]];
    for(int i=0;i<256;++i) {
        p=(double)cnt[i]/len;
        if(p==0) continue;
        else res+=(p*(log(p)/log(256)));
    }

    return -(res);
}

void resultSaving(string savdir) {
    //unordered_map<string,pair<bool,vector<Instance>>> h_instance;
    int numCount=1;

    //-------------
    // Port Saving
    //-------------
    ofstream out;
    cout<<"\nSaving to "<<savdir+(string)OUT_PTBAG<<endl;
    out.open(savdir+(string)OUT_PTBAG);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_PTBAG<<" open failed."<<endl;
        exit(1);
    }

    //Head
    //out<<"No,MAC addr";
    out<<"MAC_addr,label";
    for(int i=0;i<pt_vec.size();++i) out<<','<<pt_vec[i];
    out<<endl;

    //Content
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) {
            //out<<to_string(numCount++)<<','<<(*it).first;
            out<<(*it).first<<','<<(*it).second.second[i].device_class;
            for(int j=0;j<RPN_DIM;++j) {
                out<<','<<to_string((*it).second.second[i].stage0.rpn[j]);
            }
            out<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";

    //numCount=1;

    //---------------
    // Domain Saving
    //---------------
    cout<<"Saving to "<<savdir+(string)OUT_DMBAG<<endl;
    out.open(savdir+(string)OUT_DMBAG);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_DMBAG<<" open failed."<<endl;
        exit(1);
    }

    //Head
    //out<<"No,MAC addr";
    out<<"MAC_addr,label";
    for(int i=0;i<dm_vec.size();++i) out<<','<<dm_vec[i];
    out<<endl;

    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) {
            //out<<to_string(numCount++)<<','<<(*it).first;
            out<<(*it).first<<','<<(*it).second.second[i].device_class;
            for(int j=0;j<DM_DIM;++j) {
                out<<','<<to_string((*it).second.second[i].stage0.dm[j]);
            }
            out<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";

    //numCount=1;

    //---------------------
    // Cipher Suite Saving
    //---------------------
    cout<<"Saving to "<<savdir+(string)OUT_CSBAG<<endl;
    out.open(savdir+(string)OUT_CSBAG);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_CSBAG<<" open failed."<<endl;
        exit(1);
    }

    //Head
    //out<<"No,MAC addr";
    out<<"MAC_addr,label";
    for(int i=0;i<cs_vec.size();++i) out<<','<<cs_vec[i];
    out<<endl;

    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) {
            //out<<to_string(numCount++)<<','<<(*it).first;
            out<<(*it).first<<','<<(*it).second.second[i].device_class;

            for(int j=0;j<CS_DIM;++j) {
                out<<','<<to_string((*it).second.second[i].stage0.cs[j]);
            }
            out<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";

    //numCount=1;

    //-----------
    // Stage One
    //-----------
    cout<<"Saving to "<<savdir+(string)OUT_STAGE1<<endl;
    out.open(savdir+(string)OUT_STAGE1);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_STAGE1<<" open failed."<<endl;
        exit(1);
    }
    //Head
    out<<"MAC_addr,label,flow_volume,flow_duration,flow_rate,sleep_time,dns_interval,ntp_interval"<<endl;
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) {
            if((*it).second.second[i].stage1.flow_rate==0) {
                (*it).second.second[i].stage1.flow_rate=(double)(*it).second.second[i].stage1.flow_volume/3600/1024;
            }
            //out<<to_string(numCount++)<<','<<(*it).first;
            out<<(*it).first<<','<<(*it).second.second[i].device_class<<',';
            out<<to_string((*it).second.second[i].stage1.flow_volume)<<','<<    // B
                to_string((*it).second.second[i].stage1.flow_duration/1000000)<<','<<  // s
                to_string((*it).second.second[i].stage1.flow_rate*1024)<<','<< // B/s
                to_string((*it).second.second[i].stage1.sleep_time/1000000)<<','<<
                to_string((*it).second.second[i].stage1.dns_interval/1000000)<<','<<
                to_string((*it).second.second[i].stage1.ntp_interval/1000000)<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";

    //--------------------
    // New Feature Saving
    //--------------------
    cout<<"Saving to "<<savdir+(string)OUT_NWFEATURE<<endl;
    out.open(savdir+(string)OUT_NWFEATURE);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_NWFEATURE<<" open failed."<<endl;
        exit(1);
    }
    out<<"MAC_addr,label,avg_win,avg_mss,avg_sen,"<<
         "ip_cnt,df_cnt,icmp_cnt,tcp_cnt,udp_cnt,http_cnt,dhcp_cnt,dns_cnt,ntp_cnt"<<endl;
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) {
            Instance* ins=&((*it).second.second[i]);
            out<<(*ins).mac_adr<<','<<(*ins).device_class<<','<<(*ins).avg_rwin<<','<<
                (*ins).avg_mss<<','<<(*ins).avg_sen<<','<<(*ins).ip_cnt<<','<<
                (*ins).df_flag_cnt<<','<<(*ins).icmp_cnt<<','<<(*ins).tcp_cnt<<','<<
                (*ins).udp_cnt<<','<<(*ins).http_cnt<<','<<(*ins).dhcp_cnt<<','<<
                (*ins).stage1.dns_interval_count+1<<','<<(*ins).stage1.ntp_interval_count+1<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";

    //---------------------
    // Minute Distribution
    //---------------------
    cout<<"Saving to "<<savdir+(string)OUT_MINDIS<<endl;
    out.open(savdir+(string)OUT_MINDIS);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_MINDIS<<" open failed."<<endl;
        exit(1);
    }
    out<<"MAC_addr,label";
    for(int i=0;i<59;++i) out<<",min_"<<to_string(i+1);
    out<<endl;
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) {
            Instance* ins=&((*it).second.second[i]);
            out<<(*ins).mac_adr<<','<<(*ins).device_class;
            for(int j=0;j<59;++j) {
                out<<','<<(*ins).min_pck_cnt[j];
            }
            out<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";

    //-------------
    // Info Saving
    //-------------
    cout<<"Saving to "<<savdir+(string)OUT_INFO<<endl;
    out.open(savdir+(string)OUT_INFO);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_INFO<<" open failed."<<endl;
        exit(1);
    }
    //Head
    out<<"No,MAC_addr,device_class,instance_num"<<endl;
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        if(iotMap.count((*it).first)!=0) {
            out<<to_string(numCount++)<<','<<(*it).first<<','<<
                to_string(iotMap[(*it).first])<<','<<
                to_string((*it).second.second.size())<<endl;
        }
        else {
            out<<to_string(numCount++)<<','<<(*it).first<<','<<
                to_string(NONIOTCLASS)<<','<<
                to_string((*it).second.second.size())<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";
}

string arrayEncoding(u_int* array, int dimention) {
    string res;
    for(int i=0;i<dimention;++i) {
        res+=to_string(array[i])+":";
    }
    res.pop_back();
    return res;
}

void raw_saving(string data_dir) {
    ofstream out;
    cout<<"\nSaving to "<<data_dir+(string)OUT_ORIGIN<<endl;
    out.open(data_dir+(string)OUT_ORIGIN);
    if (out.fail()) {
        cout<<"Output file "<<data_dir+(string)OUT_ORIGIN<<" open failed."<<endl;
        exit(1);
    }
    //Head
    out<<"MAC_addr,label,occur_count,rpn,dm,cs,flow_volume,flow_rate,flow_duration,"<<
    "sleep_time,sleep_time_count,dns_interval,dns_interval_count,"<<
    "ntp_interval,ntp_interval_count"<<endl;

    //Content
    //unordered_map<string,pair<bool,vector<Instance>>> h_instance;
    for(unordered_map<string,pair<bool,vector<Instance>>>::iterator it=h_instance.begin();
        it!=h_instance.end();++it) {
        for(int i=0;i<(*it).second.second.size();++i) { //instance list
            Instance ins=(*it).second.second[i];
            out<<(*it).first<<','<<ins.device_class<<','<<ins.stage1.sleep_time_count<<','<<
                arrayEncoding(ins.stage0.rpn,RPN_DIM)<<','<<
                arrayEncoding(ins.stage0.dm,DM_DIM)<<','<<
                arrayEncoding(ins.stage0.cs,CS_DIM)<<','<<
                ins.stage1.flow_volume<<','<<ins.stage1.flow_rate<<','<<ins.stage1.flow_duration<<','<<
                ins.stage1.sleep_time<<','<<ins.stage1.sleep_time_count<<','<<ins.stage1.dns_interval<<','<<
                ins.stage1.dns_interval_count<<','<<ins.stage1.ntp_interval<<','<<ins.stage1.ntp_interval_count<<endl;
        }
    }
    out.close();
    cout<<"Success.\n";
}
