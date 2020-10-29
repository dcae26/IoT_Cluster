//
//  dataAnalysis.cpp
//

#include "dataAnalysis.h"

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
            if(tmp.find(strip)!=string::npos) {
                res.push_back(ddir+tmp);
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

void arrayDecoding(string code,vector<u_int>* array) {
    int last_found=0;
    for(int i=0;i<code.size();++i) {
        if(code[i]==':') {
            (*array).push_back((u_int)stoi(code.substr(last_found,i)));
            last_found=i+1;
        }
    }
    (*array).push_back((u_int)stoi(code.substr(last_found,code.size()-last_found)));
}

int main(int argc, char* argv[]) {
    if(argc != 4) {
        printf("Arguments Fault!\n");
        printf("Usage:<program> <configuration dir> <data dir> <result dir>\n");
        printf("Data Dir should include:\n");
        printf("raw_data.csv\n");
        return -1;
    }

    print_banner();

    string conf_dir=argv[1],data_dir=argv[2],res_dir=argv[3];
    if(conf_dir.back()!='/') {
        conf_dir.push_back('/');
    }
    if(data_dir.back()!='/') {
        data_dir.push_back('/');
    }
    if(res_dir.back()!='/') {
        res_dir.push_back('/');
    }

    //Alphabet initialize
    for(int i=0;i<26;++i) {
        alphabet.insert(pair<char,int>((char)('a'+i),i));
        //cout<<(char)('a'+i)<<":"<<i+1<<endl;
    }

    //Read configuration
    ifstream conf;
    cout<<"Loading Configuration...\n";
    conf.open(conf_dir + CONFIGFILE);
    if(!conf.is_open()) {
        cout<<"File "<<conf_dir + CONFIGFILE<<" open failed."<<endl;
        cout<<"Initialize the configuration? y/[n]  ";
        char ctmp;
        cin>>ctmp;
        if(ctmp=='y') {
            conf.close();
            cout<<"Initializing...  ";
            ofstream out;
            out.open(CONFIGFILE);
            out<<"0,Data Type: 0 for IoT dataset, 1 for Tunet Background Flow\n"
                <<"0,Mode:0 for Feature Vectors Statistic analysis, 1 for Raw Reconstruct\n"
                <<"16,[STA]Top N of Ports\n"
                <<"8,[STA]Top N of Domain\n"
                <<"2,[STA]Top N of Cipher Suite\n"
                <<"5,[RAW]Pck Number Filter\n"
                <<"5,[RAW]DNS Pck Number Filter\n"
                <<"0,[RAW]NTP Pck Number Filter\n"
                <<"1,[RAW]IP filter for DNS(1 or 0)\n"
                <<"1,[STO]1 for STA store with head, 0 for STA store without head\n";
            out.close();
            cout<<"Done.\nReopening...  ";
            conf.open(CONFIGFILE);
            if(!conf.is_open()) {
                cout<<"Initialize Failed.\n";
                exit(1);
            }
            else {
                cout<<"Success.\n";
            }
        }
        else {
            cout<<"Initialization Rejected.\n";
            exit(1);
        }
    }

    string line;
    getline(conf, line);
    if(line.substr(0,line.find(','))=="1") DATA_DIR=(char*)"tunet_result";
    else DATA_DIR=(char*)"result";
    getline(conf, line);mode=stoi(line.substr(0,line.find(',')));
    getline(conf, line);pt_top=stoi(line.substr(0,line.find(',')));
    getline(conf, line);dm_top=stoi(line.substr(0,line.find(',')));
    getline(conf, line);cs_top=stoi(line.substr(0,line.find(',')));
    getline(conf, line);pck_threshold=stoi(line.substr(0,line.find(',')));
    getline(conf, line);dns_threshold=stoi(line.substr(0,line.find(',')));
    getline(conf, line);ntp_threshold=stoi(line.substr(0,line.find(',')));
    getline(conf, line);use_ip_filter_dns=stoi(line.substr(0,line.find(',')));
    getline(conf, line);sto_head=stoi(line.substr(0,line.find(',')));
    //cout<<pck_threshold<<":"<<dns_threshold<<":"<<ntp_threshold<<":"<<use_ip_filter_dns<<endl;

    cout<<"Done.\n";
    conf.close();

    switch (mode) {
        case 0:
            cout<<"---Mode:Feature Vec Analysis---\n";
            mode_statistic(data_dir,res_dir);
            break;
        case 1:
            cout<<"---Mode:Raw Data Reconstruct---\n";
            mode_raw(data_dir,res_dir);
            break;
        default:
            cout<<"Mode Error! Please check the configuration file.\n";
            exit(1);
    }

    return 0;
}

void mode_statistic(string data_dir, string savdir) {
    vector<string> filelist=getFilenames(data_dir,DATA_DIR);
    vector<string> files;
    if(!filelist.empty()) {
        cout<<"[Multiple Directories Mode]\n";
        for(int i=0;i<filelist.size();++i) {
            cout<<"Reading "<<filelist[i]<<" ...";
            files.push_back(filelist[i]+'/');
            cout<<"Done.\n";
        }
    }
    else {
        cout<<"[One Directory Mode]\n";
        files.push_back(data_dir);
    }

    if(files.empty()) {
        cout<<"[ERROR] No files found!\n";
        exit(1);
    }

    cout<<"[Data Found]\n";
    for(int i=0;i<files.size();++i)
        cout<<files[i]<<endl<<endl;

    //Head of the data
    vector<string> line_code;
    string pt_head;
    string dm_head;
    string cs_head;
    string s1_head;
    string ft_head;

    getHead(files[0],&pt_head,&dm_head,&cs_head,&s1_head,&ft_head);
    sta_process(files[0],&line_code);
    for(int i=1;i<files.size();++i) {
        sta_process(files[i],&line_code);
    }

    cout<<"Instance Num:"<<line_code.size()<<endl;

    //save
    ofstream out;
    cout<<"Saving to "<<savdir+(string)OUT_ENCODE<<" ...";
    out.open(savdir+(string)OUT_ENCODE);
    if(out.fail()) {
        cout<<"File "<<data_dir<<" open failed."<<endl;
        exit(1);
    }
    //create head
    if(sto_head) {
        //out<<"label,flow_volume,flow_duration,flow_rate,sleep_time,dns_interval,ntp_interval";
        u_long index=s1_head.find(',')+1;
        s1_head=s1_head.substr(index,s1_head.size()-index);
        index=ft_head.find(',');
        index=ft_head.find(',',index+1)+1;
        ft_head=ft_head.substr(index,ft_head.size()-index);

        out<<s1_head<<','<<ft_head<<','<<SEQ_HEAD;
        //ft_head=ft_head.substr(,)

        for(int i=0;i<pt_top;++i) {
            out<<",top"<<to_string(i+1)<<"_pt_name,top"<<to_string(i+1)<<"_pt_cnt";
        }
        for(int i=0;i<dm_top;++i) {
            out<<",top"<<to_string(i+1)<<"_dm_name,top"<<to_string(i+1)<<"_dm_cnt";
        }
        for(int i=0;i<cs_top;++i) {
            out<<",top"<<to_string(i+1)<<"_cs_name,top"<<to_string(i+1)<<"_cs_cnt";
        }
        out<<endl;
    }

    for(int i=0;i<line_code.size();++i) {
        out<<line_code[i]<<endl;
    }
    out.close();
    cout<<"Done.\n";
}

void sta_process(string data_dir,vector<string>* line_code) {
    vector<string> pt,dm,cs,s1,ft;
    s1=getFeature(data_dir+(string)OUT_STAGE1,1);
    ft=getFeature(data_dir+(string)OUT_NWFEATURE,2);
    pt=getTopN(data_dir+(string)OUT_PTBAG,pt_top);
    dm=getTopN(data_dir+(string)OUT_DMBAG,dm_top);
    cs=getTopN(data_dir+(string)OUT_CSBAG,cs_top);

    if(s1.size()==pt.size()==dm.size()==cs.size()) {
        cout<<"Data in "<<data_dir<<" dimention error, please check.\n";
        exit(1);
    }

    for(int i=0;i<s1.size();++i) {
        (*line_code).push_back(s1[i]+','+ft[i]+",0,0,"+pt[i]+','+dm[i]+','+cs[i]);
    }
}

vector<string> getFeature(string data_dir,int skip_col) {
    cout<<"Geting "<<data_dir<<" data...";
    vector<string> res;

    ifstream inStream;
    inStream.open(data_dir,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<data_dir<<" open failed."<<endl;
        exit(1);
    }

    string line,data;
    getline(inStream,line,'\n');//skip head
    while (getline(inStream,line,'\n')) {
        istringstream tmpline(line);
        for(int i=0;i<skip_col;++i) getline(tmpline,data,','); //skip col
        getline(tmpline,data,'\n');
        //line=line.substr(line.find(',')+1,line.size()-line.find(','));
        res.push_back(data);
    }

    cout<<"  Done.\n";
    return res;
}

vector<string> getTopN(string data_dir,int topNum) {
    cout<<"Geting Top "<<topNum<<" data in "<<data_dir<<endl;

    vector<string> res;
    int data_dim=0;
    if(data_dir.find("ports")!=string::npos) {
        data_dim=RPN_DIM;
    }
    else if(data_dir.find("domain")!=string::npos) {
        data_dim=DM_DIM;
    }
    else if(data_dir.find("cipher_suite")!=string::npos) {
        data_dim=CS_DIM;
    }
    else {
        cout<<"Get TopN data_dir unexpected.\n";
        exit(1);
    }

    ifstream inStream;
    inStream.open(data_dir,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<data_dir<<" open failed."<<endl;
        exit(1);
    }

    string line;
    string data;
    u_int index=1;
    vector<pair<u_int,u_int>> topN;
    u_int instance_num=0;
    getline(inStream,line);//skip head
    while (getline(inStream,line))
    {
        cout<<"Raw Instance Processed:"<<++instance_num;

        topN.clear();
        index=1;

        istringstream tmpline(line);

        getline(tmpline,data,',');getline(tmpline,data,',');//skip addr and label
        while(getline(tmpline,data,',')) {
            u_int cnt=stoi(data);
            if(cnt==0) { //skip zero
                ++index;
            }
            else {
                if(data_dim==RPN_DIM) { //port name
                    index==RPN_DIM?
                    topN.push_back(pair<u_int,u_int>(PT_OTHER,cnt)):
                    topN.push_back(pair<u_int,u_int>(stoi(pt_vec[index-1]),cnt));
                    ++index;
                }
                else if(data_dim==DM_DIM) { //domain
                    index==DM_DIM?
                    topN.push_back(pair<u_int,u_int>(DM_OTHER,cnt)):
                    topN.push_back(pair<u_int,u_int>(domain_encoding(dm_vec[index-1]),cnt));
                    ++index;
                }
                else if(data_dim==CS_DIM) { //cipher suite
                    index==CS_DIM?
                    topN.push_back(pair<u_int,u_int>(CS_OTHER,cnt)):
                    topN.push_back(pair<u_int,u_int>(decode_cipher_suite(cs_vec[index-1]),cnt));
                    ++index;
                }
                else {
                    cout<<"Unexpected data_dim\n";
                    exit(1);
                    //topN.push_back(pair<u_int,u_int>(index++,cnt));
                }
            }
        }
        sort(topN.begin(),topN.end(),pair_dbui_cmp());

        data.clear();
        index=0;
        for(index=0;(index<topNum)&&(index<topN.size());++index) {
            data+=to_string(topN[index].first)+','+to_string(topN[index].second)+',';
        }
        while(index<topNum) { //padding
            data+="0,0,";
            ++index;
        }
        data.pop_back();
        res.push_back(data);
        cout<<"\r";
    }

    inStream.close();
    cout<<"\nDone.\n";
    return res;
}

void mode_raw(string data_dir, string savdir) {
    vector<string> filelist=getFilenames(data_dir,DATA_DIR);
    vector<string> files;
    if(!filelist.empty()) {
        cout<<"[Multiple Directories Mode]\n";
        for(int i=0;i<filelist.size();++i) {
            cout<<"Reading "<<filelist[i]<<" ...";
            files.push_back(findRaw(getFilenames(filelist[i]+'/',".csv")));
            cout<<"Done.\n";
        }
    }
    else {
        cout<<"[One Directory Mode]\n";
        files.push_back(findRaw(getFilenames(data_dir,".csv")));
    }

    if(files.empty()) {
        cout<<"[ERROR] No files found!\n";
        exit(1);
    }

    cout<<"[Data Found]\n";
    for(int i=0;i<files.size();++i)
        cout<<files[i]<<endl;
    //    for(int i=0;i<files.size();++i)
    //        for(int j=0;j<files[i].size();++j)
    //            cout<<files[i][j]<<endl;

    //head content of data
    vector<RawInstance> raw_data;
    string filedir;

    string pt_head;
    string dm_head;
    string cs_head;
    string s1_head;
    string ft_head;

    filedir=files[0].substr(0,files[0].size()-((string)OUT_ORIGIN).size());
    getHead(filedir,&pt_head,&dm_head,&cs_head,&s1_head,&ft_head);

    raw_process(files[0],&raw_data);

    for(int i=1;i<files.size();++i) {
        raw_process(files[i],&raw_data);
    }

    //Restore
    ofstream out;

    //-------------
    // Port Saving
    //-------------
    cout<<"\nSaving to "<<savdir+(string)OUT_PTBAG<<endl;
    out.open(savdir+(string)OUT_PTBAG);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_PTBAG<<" open failed."<<endl;
        exit(1);
    }
    out<<pt_head;
    for(int i=0;i<raw_data.size();++i) {
        out<<raw_data[i].ip_addr<<','<<raw_data[i].label;
        for(int j=0;j<RPN_DIM;++j) {
            out<<','<<raw_data[i].pt[j];
        }
        out<<endl;
    }
    out.close();
    cout<<"Success.\n";

    //---------------
    // Domain Saving
    //---------------
    cout<<"Saving to "<<savdir+(string)OUT_DMBAG<<endl;
    out.open(savdir+(string)OUT_DMBAG);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_DMBAG<<" open failed."<<endl;
        exit(1);
    }
    out<<dm_head;
    for(int i=0;i<raw_data.size();++i) {
        out<<raw_data[i].ip_addr<<','<<raw_data[i].label;
        for(int j=0;j<DM_DIM;++j) {
            out<<','<<raw_data[i].dm[j];
        }
        out<<endl;
    }
    out.close();
    cout<<"Success.\n";

    //---------------------
    // Cipher Suite Saving
    //---------------------
    cout<<"Saving to "<<savdir+(string)OUT_CSBAG<<endl;
    out.open(savdir+(string)OUT_CSBAG);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_CSBAG<<" open failed."<<endl;
        exit(1);
    }
    out<<cs_head;
    for(int i=0;i<raw_data.size();++i) {
        out<<raw_data[i].ip_addr<<','<<raw_data[i].label;
        for(int j=0;j<CS_DIM;++j) {
            out<<','<<raw_data[i].cs[j];
        }
        out<<endl;
    }
    out.close();
    cout<<"Success.\n";

    //-----------
    // Stage One
    //-----------
    //IP addr,label,flow_volume,flow_duration,flow_rate,sleep_time,dns_interval,ntp_interval
    out.open(savdir+"dn_usec.csv");

    cout<<"Saving to "<<savdir+(string)OUT_STAGE1<<endl;
    out.open(savdir+(string)OUT_STAGE1);
    if (out.fail()) {
        cout<<"Output file "<<savdir+(string)OUT_STAGE1<<" open failed."<<endl;
        exit(1);
    }
    out<<s1_head;
    for(int i=0;i<raw_data.size();++i) {
        if(raw_data[i].flow_rate==0) {
            raw_data[i].flow_rate=(double)raw_data[i].flow_volume/3600/1024;
        }
        out<<raw_data[i].ip_addr<<','<<raw_data[i].label<<','<<
            raw_data[i].flow_volume<<','<< //B
            raw_data[i].flow_duration/1000000<<','<<  //s
            raw_data[i].flow_rate*1024<<','<<  //B/s
            raw_data[i].sleep_time/1000000<<','<<
            raw_data[i].dns_interval/1000000<<','<<
            raw_data[i].ntp_interval/1000000<<endl;
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
    out<<"IP addr,device_class,instance_num,occur_packet,DNS_num,NTP_num"<<endl;
    for(unordered_map<string,vector<u_long>>::iterator it=instance_cnt.begin();
        it!=instance_cnt.end();++it) {
        out<<(*it).first;
        for(int i=0;i<(*it).second.size();++i) {
            out<<','<<(*it).second[i];
        }
        out<<endl;
    }
    out.close();
    cout<<"Success.\n";
}

void raw_process(string raw_data,vector<RawInstance>* raw) {
    //IP addr,label,occur_count,rpn,dm,cs,flow_volume,flow_rate,flow_duration,
    //sleep_time,sleep_time_count,dns_interval,dns_interval_count,
    //ntp_interval,ntp_interval_count

    ifstream file;
    file.open(raw_data,ios::in);
    if(file.fail()) {
        cout<<"File "<<raw_data<<" open failed."<<endl;
        exit(1);
    }

    cout<<"Processing "<<raw_data<<" ...\n";
    string line;
    u_long instance_num=0;

    getline(file,line,'\n');//skip head

    while (getline(file,line,'\n'))
    {
        cout<<"\rRaw Instance Processed:"<<++instance_num;
        istringstream tmpline(line);
        string data;
        RawInstance instance;

        //bag feature initialize
        instance.pt=vector<u_int>(RPN_DIM,0);
        instance.dm=vector<u_int>(DM_DIM,0);
        instance.cs=vector<u_int>(CS_DIM,0);

        getline(tmpline,data,',');instance.ip_addr=data;
        if(ip_filter(data)) continue;
        getline(tmpline,data,',');instance.label=stoi(data);
        getline(tmpline,data,',');instance.occur_count=stoul(data);
        getline(tmpline,data,',');arrayDecoding(data,&(instance.pt));
        getline(tmpline,data,',');arrayDecoding(data,&(instance.dm));
        getline(tmpline,data,',');arrayDecoding(data,&(instance.cs));
        getline(tmpline,data,',');instance.flow_volume=stoul(data);
        getline(tmpline,data,',');instance.flow_rate=stod(data);
        getline(tmpline,data,',');instance.flow_duration=stoul(data);
        getline(tmpline,data,',');instance.sleep_time=stod(data);
        getline(tmpline,data,',');instance.sleep_time_count=stoul(data);
        getline(tmpline,data,',');instance.dns_interval=stod(data);
        getline(tmpline,data,',');instance.dns_interval_count=stoul(data);
        getline(tmpline,data,',');instance.ntp_interval=stod(data);
        getline(tmpline,data,',');instance.ntp_interval_count=stoul(data);
        if(pck_filter(instance.occur_count,instance.dns_interval_count,instance.ntp_interval_count))
            continue;

        (*raw).push_back(instance);

        if(instance_cnt.count(instance.ip_addr)==0) {
            instance_cnt.insert(pair<string,vector<u_long>>(instance.ip_addr,vector<u_long>
            ({(u_long)instance.label,1,instance.occur_count,instance.dns_interval_count,instance.ntp_interval_count})));
        }
        else {
            if(instance.label!=instance_cnt[instance.ip_addr][0]) {
                cout<<"Unexpected label unmatch!\n";
                cout<<"IP addr:"<<instance.ip_addr<<endl;
                exit(1);
            }
            ++instance_cnt[instance.ip_addr][1];
            instance_cnt[instance.ip_addr][2]+=instance.occur_count;
            instance_cnt[instance.ip_addr][3]+=instance.dns_interval_count;
            instance_cnt[instance.ip_addr][4]+=instance.ntp_interval_count;
        }
    }
    file.close();
    cout<<"\nDone.\n";
    cout<<"Current Instance Num:"<<(*raw).size()<<endl;
}

string findRaw(vector<string> data) {
    for(int i=0;i<data.size();++i) {
        if(data[i].find(OUT_ORIGIN)!=string::npos) {
            return data[i];
        }
    }
    cout<<"\n[ERROR] "<<OUT_ORIGIN<<" not found!\n";
    exit(1);
}

void getHead(string filedir,string* pt_head,string* dm_head,
             string* cs_head,string* s1_head,string* ft_head) {
    ifstream inStream;
    string line;
    string data;

    inStream.open(filedir+(string)OUT_PTBAG,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<filedir+(string)OUT_PTBAG<<" open failed."<<endl;
        exit(1);
    }
    getline(inStream,line);
    (*pt_head)=line;
    istringstream tmpline(line);
    getline(tmpline,data,',');getline(tmpline,data,',');//skip ip_addr and label
    while (getline(tmpline,data,',')) pt_vec.push_back(data);
    inStream.close();

    inStream.open(filedir+(string)OUT_DMBAG,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<filedir+(string)OUT_DMBAG<<" open failed."<<endl;
        exit(1);
    }
    getline(inStream,line);
    (*dm_head)=line;
    tmpline.clear();
    tmpline.str(line);
    getline(tmpline,data,',');getline(tmpline,data,',');//skip ip_addr and label
    while (getline(tmpline,data,',')) dm_vec.push_back(data);
    inStream.close();

    inStream.open(filedir+(string)OUT_CSBAG,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<filedir+(string)OUT_CSBAG<<" open failed."<<endl;
        exit(1);
    }
    getline(inStream,line);
    (*cs_head)=line;
    tmpline.clear();
    tmpline.str(line);
    getline(tmpline,data,',');getline(tmpline,data,',');//skip ip_addr and label
    while (getline(tmpline,data,',')) cs_vec.push_back(data);
    inStream.close();

    inStream.open(filedir+(string)OUT_STAGE1,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<filedir+(string)OUT_STAGE1<<" open failed."<<endl;
        exit(1);
    }
    getline(inStream,line);
    (*s1_head)=line;
    inStream.close();

    inStream.open(filedir+(string)OUT_NWFEATURE,ios::in);
    if(inStream.fail()) {
        cout<<"File "<<filedir+(string)OUT_NWFEATURE<<" open failed."<<endl;
        exit(1);
    }
    getline(inStream,line);
    (*ft_head)=line;
    inStream.close();
}

bool ip_filter(string ip_addr) {
    if(use_ip_filter_dns) {
        if(ip_filter_dns.count(ip_addr)!=0)
            return true;
    }
    return false;
}

bool pck_filter(u_long pck,u_long dns,u_long ntp) {
    if(pck<pck_threshold||dns<dns_threshold||ntp<ntp_threshold) {
        return true;
    }
    return false;
}

u_int domain_encoding(string dm) {
    return edit_distance(dm);
}

u_int edit_distance(string str2) {
    string str1=(string)ED_DM_BASE;
    if(str1==str2) return 0;

    u_int d[str1.size()+1][str2.size()+1];

    for (int i=0;i<=str1.size();++i) d[i][0]=i;
    for (int j=0;j<=str2.size();++j) d[0][j]=j;

    for (int i=1;i<=str1.size();++i) {
        for (int j=1;j<=str2.size();++j) {
            if (str1[i-1]==str2[j-1]) {
                d[i][j]=d[i-1][j-1];
            }
            else {
                //min of three
                (d[i-1][j]+1)<(d[i][j-1]+1)?
                d[i][j]=(d[i-1][j]+1):d[i][j]=d[i][j-1]+1;
                d[i][j]<(d[i-1][j-1]+1)?d[i][j]=d[i][j]:d[i][j]=d[i-1][j-1]+1;
                //d[i][j]=min_of_three(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+1);
            }
        }//for j
    }//for i

    return d[str1.size()][str2.size()];
}

u_int decode_cipher_suite(string cs) {
    cs=cs.substr(1,cs.size()-2);
    u_int code=0;
    for(int i=0;i<cs.size();i+=5) {
        code+=stoi(cs.substr(i,4),nullptr,16);
    }
    return code;
}
