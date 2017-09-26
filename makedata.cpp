#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <map>
#include "radio.h"
#include "save_key_value.h"
using namespace std;
//키벨류를 구조체를 포인터로 쓰는게 더 낫지 않을까?

void makedata(struct pcap_pkthdr *pkthdr,const u_char *packet)
{

    int packet_len = pkthdr->caplen;
    const char *empty="(not associated)";
    struct radiotap_header *rh = (struct radiotap_header*)packet;
    packet += rh->header_len;
    struct ieee80211_common *c = (struct ieee80211_common *)packet;

    if(c->Type == 0)
    {
        switch(c->Sutype)
        {

            case 0:
            {
                struct key_Association_res Ar;
                struct value_Association_res vA;
                cout << "Association request" <<endl;
                struct ieee80211_Association *A = (struct ieee80211_Association*)packet;
                memset(Ar.Association_res_save_BSSID,0,6);
                memset(vA.dst_addr,0,6);
                memset(vA.src_addr,0,6);
                memcpy(Ar.Association_res_save_BSSID,A->BSSID,6);
                memcpy(vA.dst_addr,A->Dst_addr,6);
                memcpy(vA.src_addr,A->Src_addr,6);
                packet += sizeof(struct ieee80211_Association) + sizeof(struct ieee80211_wireless_LAN_mg_Association);
                int a{0}; //check point
                while(1)
                {
                    if(a==1)//case 0 선택됬을경우 프로그램 종료
                        break;
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    memset(vA.A_req_ESSID,0,32);

                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);
                             memcpy(vA.A_req_ESSID, packet,Tc->TagLen);
                             cout << vA.A_req_ESSID << endl;
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                             a=1;//check point
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                        }
                        break;
                    }

                }

            }
            break;

            case 1:
                cout << "Association response" <<endl;
            break;

            case 2:
            {
                struct key_Reassociation_req Rr;
                struct value_Reassociation_req vR;
                cout << "Reassociation request" <<endl;
                struct ieee80211_Ressociation *R = (struct ieee80211_Ressociation*)packet;
                memset(Rr.Reassociation_req_save_BSSID,0,6);
                memset(vR.src_addr,0,6);
                memset(vR.dst_addr,0,6);
                memcpy(Rr.Reassociation_req_save_BSSID,R->BSSID,6);
                memcpy(vR.src_addr,R->Src_addr,6);
                memcpy(vR.dst_addr,R->Dst_addr,6);
                packet += sizeof(struct ieee80211_Ressociation) + sizeof(struct ieee80211_wireless_LAN_mg_Reassociation);
                int a{0};
                while(1)
                {
                    if(a==1)//case 0 선택됬을경우 프로그램 종료
                        break;
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    if(Tc->TagLen==0) break;
                    memset(vR.Rea_req_ESSID,0,32);
                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);
                             memcpy(vR.Rea_req_ESSID, packet,Tc->TagLen);
                             cout << vR.Rea_req_ESSID << endl;
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                             a=1;//check point
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                        }
                        break;
                    }

                }

            }
            break;

            case 3:
                cout << "Reassociation response" <<endl;
            break;

            case 4:
            {
                struct key_probe_req kpr;
                struct value_probe_req vpr;
                cout << "Probe_Request" << endl;
                struct ieee80211_Probe_Request *PRQ = (struct ieee80211_Probe_Request*)packet;
                memset(kpr.probe_save_bssid,0,6);
                memset(vpr.src,0,6);
                memcpy(kpr.probe_save_bssid,PRQ->BSSID,6);
                memcpy(vpr.src,PRQ->Src_addr,6);

                packet += sizeof(struct ieee80211_Probe_Request);
                int a{0},b{0};
                while(1)
                {
                    if(a==1 && b==1)//case 0과 case 3이 모두 선택됬을경우 프로그램 종료
                        break;
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    if(Tc->TagLen==0)//SSID 가 없을 때가 있음
                    {
                       memcpy(vpr.probe_ESSID,empty,strlen(empty));
                       cout << vpr.probe_ESSID <<endl;
                       break;
                    }
                    memset(vpr.probe_ESSID,0,32);
                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);
                             memcpy(vpr.probe_ESSID, packet,Tc->TagLen);
                             cout << "Probe ESSID = "<< vpr.probe_ESSID << endl;

                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;

                             a=1;//check point  `
                        }
                        break;

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             memcpy(&vpr.probe_current_channel, &DS->Current_Channel, 1);
                             printf("## Current channel = %d\n", vpr.probe_current_channel);
                             packet += sizeof(struct Tagpara_common);

                              packet += Tc->TagLen;
                              packet_len -=Tc->TagLen;

                             b=1; //check point
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);

                             packet += Tc->TagLen;
                             packet_len -=Tc->TagLen;

                        }
                        break;

                     }
                 }
            }
            break;

            case 5:
            {
                struct key_probe_res kps;
                struct value_probe_res vps;
                cout << "Probe Response" <<endl;
                struct ieee80211_Probe_Response *PRS = (struct ieee80211_Probe_Response*)packet;
                memset(kps.probe_save_bssid,0,6);
                memset(vps.src,0,6);
                memcpy(kps.probe_save_bssid,PRS->BSSID,6);
                memcpy(vps.src,PRS->Src_addr,6);
                packet += sizeof(struct ieee80211_Probe_Response) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);
                int a{0},b{0}; //check point
                while(1)
                {
                    if(a==1 && b==1)//case 0과 case 3이 모두 선택됬을경우 프로그램 종료
                        break;
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    memset(vps.probe_ESSID,0,32);
                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);
                             memcpy(vps.probe_ESSID, packet,Tc->TagLen);
                             cout << vps.probe_ESSID << endl;
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                             a=1;//check point
                        }
                        break;

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             memcpy(&vps.probe_current_channel, &DS->Current_Channel, 1);
                             printf("## Current channel = %d\n", vps.probe_current_channel);
                             packet += sizeof(struct Tagpara_common);
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                             b=1; //check point
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                        }
                        break;
                     }
                 }
            }
            break;

            case 8:
            {
                struct key_beacon k;
                struct value_beacon v;
                cout << "Beacon frame" <<endl;
                memset(k.save_bssid,0,6);
                struct ieee80211_Beacon_frame *BF = (struct ieee80211_Beacon_frame*)packet;
                memcpy(k.save_bssid,BF->BSSID,6);
                packet += sizeof(struct ieee80211_Beacon_frame) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);

                int a{0},b{0}; //check point

                while(1)
                {
                    if(a==1 && b==1)//case 0과 case 3이 모두 선택됬을경우 프로그램 종료
                        break;

                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    memset(v.ESSID,0,32);
                    switch(Tc->TagNum)
                    {

                        case 0:
                        {

                             packet += sizeof(struct Tagpara_common);
                             memcpy(v.ESSID, packet,Tc->TagLen);
                             cout << v.ESSID << endl;
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                             a=1;//check point
                        }
                        break;

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             memcpy(&v.current_channel, &DS->Current_Channel, 1);
                             cout << "## Current channel = "<< (int)v.current_channel <<endl;
                             packet += sizeof(struct Tagpara_common);
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                             b=1; //check point
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(packet_len < Tc->TagLen)
                                 break;
                             else if(Tc->TagLen!=0)
                             {
                                packet += Tc->TagLen;
                                packet_len -=Tc->TagLen;
                             }
                        }
                        break;
                     }
                }
            }
            break;

            case 11:
                cout << "Authentication" <<endl;
            break;

            case 12:
                cout << "Deauthentication" <<endl;
            break;

            case 13:
                cout <<"Action"<<endl;
            break;
        }
    }
    else if(c->Type == 1)
    {
        switch(c->Sutype)
        {
            case 8:
                cout<<"Block Ack Request" <<endl;
            break;

            case 9:
                cout<<"Block Ack" <<endl;
            break;

            case 11:
                cout<<"Request to send"<<endl;
            break;

            case 12:
                cout<<"Clear to send"<<endl;
            break;

            case 13:
                cout<<"Acknowledgment"<<endl;
            break;
        }
    }
    else if(c->Type == 2)
    {
        switch(c->Sutype)
        {
            case 8:
            {
                struct key_QosData KQ;
                struct value_QosData vQ;
                cout<<"Qos Data"<<endl;
                struct ieee80211_Qos_Data *QD = (struct ieee80211_Qos_Data*)packet;
                memcpy(KQ.Qos_save_BSSID,QD->BSSID,6);
                memcpy(vQ.Dst,QD->Dst_addr,6);
                memcpy(vQ.STA_addr,QD->STA,6);
            }
            break;

            case 0:
                cout<<"Data"<<endl;
            break;
        }
    }

}
