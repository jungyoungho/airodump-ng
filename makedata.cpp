#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <map>
#include "radio.h"
#include "save_key_value.h"
using namespace std;


void makedata(struct pcap_pkthdr *pkthdr,const u_char *packet)
{

    map<struct key_beacon, struct value_beacon>beacon;
    map<struct key_probe_req, struct value_probe_req>probe_req;
    map<struct key_probe_res, struct value_probe_res>probe_res;
    map<struct key_Reassociation_req, struct value_Reassociation_req>Reassociation_req;
    map<struct key_Reassociation_res, struct value_Reassociation_res>Reassociation_res;
    map<struct key_QosData, struct value_QosData>Qos;

    int packet_len = pkthdr->caplen;
    struct radiotap_header *rh = (struct radiotap_header*)packet;
    packet += rh->header_len;
    struct ieee80211_common *c = (struct ieee80211_common *)packet;

    if(c->Type == 0)
    {
        switch(c->Sutype)
        {
            case 0:
                cout << "Association request" <<endl;
            break;

            case 1:
                cout << "Association response" <<endl;
            break;

            case 2:
                cout << "Reassociation request" <<endl;
            break;

            case 3:
                cout << "Reassociation response" <<endl;
            break;

            case 4:
            {
                struct key_probe_req kp;
                struct value_probe_req vp;
                cout << "Probe Request" <<endl;
                struct ieee80211_Probe_Request *PR = (struct ieee80211_Probe_Request*)packet;
                memcpy(kp.probe_save_bssid,PR->BSSID,6);
                memcpy(vp.src,PR->Src_addr,6);
                packet += sizeof(struct ieee80211_Probe_Request);
                while(packet_len!=0)   // 함수화하기
                {
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    if(Tc->TagLen==0) break;

                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);

                             uint8_t BOX[Tc->TagLen]{0};
                             memcpy(BOX, packet, Tc->TagLen);
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",BOX[i]);
                             printf("\n");

                             /*
                             memcpy(&vp.ESSID[0], packet,Tc->TagLen); //안되는 이유를 모르겠음..
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",vp.ESSID[i]);
                             printf("\n");
                             */

                             if(Tc->TagLen!=0)
                                packet += Tc->TagLen;
                        }
                        break;

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             vp.probe_current_channel = DS->Current_Channel;
                             printf("## Current channel = %d\n", vp.probe_current_channel);
                             packet += sizeof(struct Tagpara_common);
                             if(Tc->TagLen!=0)
                                packet+=Tc->TagLen;
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(Tc->TagLen!=0)
                                packet += Tc->TagLen;
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
                memcpy(kps.probe_save_bssid,PRS->BSSID,6);
                memcpy(vps.src,PRS->Src_addr,6);
                packet += sizeof(struct ieee80211_Probe_Response) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);
                while(packet_len!=0)   // 함수화하기
                {
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    if(Tc->TagLen==0) break;

                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);

                             uint8_t BOX[Tc->TagLen]{0};
                             memcpy(BOX, packet, Tc->TagLen);
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",BOX[i]);
                             printf("\n");

                             /*
                             memcpy(&vp.ESSID[0], packet,Tc->TagLen); //안되는 이유를 모르겠음..
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",vp.ESSID[i]);
                             printf("\n");
                             */
                             if(Tc->TagLen!=0)
                                packet += Tc->TagLen;
                        }
                        break;

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             vps.probe_current_channel = DS->Current_Channel;
                             printf("## Current channel = %d\n", vps.probe_current_channel);
                             packet += sizeof(struct Tagpara_common);
                             if(Tc->TagLen!=0)
                                packet+=Tc->TagLen;
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(Tc->TagLen!=0)
                                packet += Tc->TagLen;
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

                struct ieee80211_Beacon_frame *BF = (struct ieee80211_Beacon_frame*)packet;
                memcpy(k.save_bssid,BF->BSSID,6);
                packet += sizeof(struct ieee80211_Beacon_frame) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);

                while(packet_len!=0)
                {
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    if(Tc->TagLen==0) break;

                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);

                             uint8_t BOX[Tc->TagLen]{0};
                             memcpy(BOX, packet, Tc->TagLen);
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",BOX[i]);
                             printf("\n");


                             /*
                             memcpy(&v.ESSID[0], packet,Tc->TagLen); //안되는 이유를 모르겠음..
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",v.ESSID[i]);
                             printf("\n");
                             */

                             if(Tc->TagLen!=0)
                                packet += Tc->TagLen;

                        }
                        break;

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             v.current_channel = DS->Current_Channel;
                             printf("## Current channel = %d\n", v.current_channel);
                             packet += sizeof(struct Tagpara_common);
                             if(Tc->TagLen!=0)
                                packet+=Tc->TagLen;
                        }
                        break;

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             if(Tc->TagLen!=0)
                                packet += Tc->TagLen;
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
