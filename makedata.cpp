#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include "radio.h"

using namespace std;

struct key
{
    uint8_t save_bssid[6];
};

struct value
{
    uint8_t current_channel;
    uint8_t ESSID[32]; //Maximum 32 length
};

void makedata(struct pcap_pkthdr *pkthdr,const u_char *packet)
{
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
                cout << "Probe request" <<endl;
            break;

            case 5:
                cout << "Probe response" <<endl;
            break;

            case 8:
            {
                cout << "Beacon frame" <<endl;
                struct key k;
                struct value v;

                struct ieee80211_Beacon_frame *BF = (struct ieee80211_Beacon_frame*)packet;
                memcpy(k.save_bssid,BF->BSSID,6);

                packet += sizeof(struct ieee80211_Beacon_frame) + sizeof(struct ieee80211_wireless_LAN_mg_Beacon);

                while(1) //fix?
                {
                    struct Tagpara_common *Tc = (struct Tagpara_common*)packet;
                    if(Tc->TagLen==0) break;
                    switch(Tc->TagNum)
                    {
                        case 0:
                        {
                             packet += sizeof(struct Tagpara_common);
                             memcpy(v.ESSID, packet, Tc->TagLen);
                             for(int i=0; i<Tc->TagLen;i++)
                                printf("%c",v.ESSID[i]);
                             printf("\n");
                             packet += Tc->TagLen;
                             break;
                        }

                        case 3:
                        {
                             struct Tagpara_DS_para_set *DS = (struct Tagpara_DS_para_set*)packet;
                             v.current_channel = DS->Current_Channel;
                             printf("## Current channel = %d\n", v.current_channel);
                             packet += sizeof(struct Tagpara_common);
                             packet+=Tc->TagLen;
                             break;
                        }

                        default:
                        {
                             packet += sizeof(struct Tagpara_common);
                             packet += Tc->TagLen;
                             break;
                        }
                    }
                }
                break; //fix???
            }
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
                cout<<"Qos Data"<<endl;
            break;

            case 0:
                cout<<"Data"<<endl;
            break;
        }
    }

}
