//
//  dataAnalysis.h
//

#pragma once
#ifndef dataAnalysis_h
#define dataAnalysis_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cmath>

#include <fstream>
#include <sstream>

#include <dirent.h>

using namespace std;

#define OUT_ORIGIN "raw_data.csv"
#define OUT_INFO "info.csv"
#define OUT_PTBAG "bag_ports.csv"
#define OUT_DMBAG "bag_domain.csv"
#define OUT_CSBAG "bag_cipher_suite.csv"
#define OUT_STAGE1 "stage1_vec.csv"
#define OUT_NWFEATURE "nw_feature.csv"

#define OUT_ENCODE "instance.csv"

#define CONFIGFILE "dataAnalysis.conf"
char* DATA_DIR;

#define CLS_OTHER_STR "__Other__"

#define SEQ_HEAD "burst,period"

//ML Dimention
#define RPN_DIM 2048
#define DM_DIM 123
#define CS_DIM 13

//edit distance base
#define ED_DM_BASE "time.nist.gov"

//Other Parameters
#define PT_OTHER 100000 //max 65535
#define DM_OTHER 1000    //max 253
#define CS_OTHER 100000*255 //max 65536*255 (approx)

//custom cmp
struct pair_dbui_cmp {
    bool operator() (const pair<double,u_int> &a, const pair<double,u_int> &b) {
        return a.second > b.second;
    }
};

struct RawInstance {
    string ip_addr;
    int label;
    u_long occur_count;

    vector<u_int> pt;
    vector<u_int> dm;
    vector<u_int> cs;

    u_long flow_volume;
    double flow_rate;//KB/s
    u_long flow_duration;

    double sleep_time;
    u_long sleep_time_count;

    double dns_interval;
    u_long dns_interval_count;

    double ntp_interval;
    u_long ntp_interval_count;
};

set<string> ip_filter_dns = {
    "101.6.6.6","166.111.4.30","166.111.8.28","101.6.6.173",
    "101.6.6.2","101.6.6.191","166.111.8.30","166.111.5.203",
    "166.111.8.31","101.6.6.172","166.111.8.29","166.111.4.5"
};

vector<string> label_name = {
    "Amazon Echo","Belkin wemo motion sensor","Belkin Wemo switch",
    "Blipcare Blood Pressure meter","Dropcam","HP Printer",
    "iHome","Insteon Camera","Insteon Camera",
    "Light Bulbs LiFX Smart Bulb","Nest Dropcam","NEST Protect smoke alarm",
    "Netatmo weather station","Netatmo Welcome","PIX-STAR Photo-frame",
    "Samsung SmartCam","Smart Things","TP-Link Day Night Cloud camera",
    "TP-Link Smart plug","Triby Speaker","Withings Aura smart sleep sensor",
    "Withings Smart Baby Monitor","Withings Smart scale","Withings Baby Monitor",
    "Non-IoT Device"
};

int mode=0;
int pt_top=1;
int dm_top=1;
int cs_top=1;
int pck_threshold=0;
int dns_threshold=0;
int ntp_threshold=0;
bool sto_head=false;
bool use_ip_filter_dns=true;

u_long instance_count=0;

//Instance Num Map
//[device_class,instance_num,occur_packet,DNS_num,NTP_num]
unordered_map<string,vector<u_long>> instance_cnt;
unordered_map<char,int> alphabet;

vector<string> pt_vec;
vector<string> dm_vec;
vector<string> cs_vec;

void print_banner() {
    cout<<"===========================================================\n"<<
    "#  _____   _______    _____ _               _             #\n"<<
    "# |_   _| |__   __|  / ____| |             | |            #\n"<<
    "#   | |  ___ | |    | |    | | __ _ ___ ___| |_ ___ _ __  #\n"<<
    "#   | | / _ \\| |    | |    | |/ _` / __/ __| __/ _ \\ '__| #\n"<<
    "#  _| || (_) | |    | |____| | (_| \\__ \\__ \\ ||  __/ |    #\n"<<
    "# |_____\\___/|_|     \\_____|_|\\__,_|___/___/\\__\\___|_|    #\n";
    cout<<"#                                                         #\n"<<
    "#               ---Data Analysis Tool---                  #\n";
    cout<<"===========================================================\n\n";
}

bool ip_filter(string ip_addr);
bool pck_filter(u_long pck,u_long dns,u_long ntp);

void raw_process(string raw_data,vector<RawInstance>* raw);
void raw_line_process(string line);
string findRaw(vector<string> data);
void getHead(string filedir,string* pt_head,string* dm_head,string* cs_head,string* s1_head,string* ft_head);

void sta_process(string data_dir,vector<string>* line_code);
vector<string> getTopN(string data_dir,int topNum);
vector<string> getFeature(string data_dir,int skip_col);
u_int domain_encoding(string dm);
u_int edit_distance(string str2);
u_int decode_cipher_suite(string cs);

void mode_raw(string data_dir, string savdir);
void mode_statistic(string data_dir, string savdir);

#endif /* dataAnalysis_h */
