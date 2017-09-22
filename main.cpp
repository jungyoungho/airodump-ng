#include <iostream>
#include <pcap.h>
#include <stdint.h>
#include <map>


using namespace std;

void makedata(struct pcap_pkthdr *pkthdr,const u_char *packet);
int main(int argc, char *argv[])
{
    if(argc!=2)
    {
        cout << "******* 인자값이 잘못되었거나 인자값이 존재하지 않습니다 *******" << endl;;
        cout << " 사용법 : interface name " << endl;
    }

    char *interface = argv[1];
    cout << " >> Interface name = "<< interface << endl;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    pcd = pcap_open_live(interface, 2048, 1 , 2000, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        return 0;
    }
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
    int res;
    while((res=pcap_next_ex(pcd, &pkthdr, &packet))>=0)
    {
        if(res==1)
        {
            makedata(pkthdr, packet);
        }
        else if(res==0)
        {
            printf(">> Time out Error\n");
            continue;
        }
        else if(res==-1)
        {
            printf(">> Error!!\n");
        }
        else if(res==-2)
        {
            printf("EOF");
        }
        else
            break;
    }

       pcap_close(pcd);
       return 0;
}


/*
map<char,int>mm;
map<int, int>mc;
map<char,int>::iterator mm_iter;
map<int,int>::iterator mc_iter;
mc[70]=70;
mm['d']=90;
mm['f']=111;

for(mm_iter = mm.begin(); mm_iter!=mm.end();mm_iter++)
{
    cout <<mm_iter->first<<" "<<mm_iter->second<<endl;
}

for(mc_iter = mc.begin(); mc_iter!=mc.end();mc_iter++)
{
    cout <<mc_iter->first<<" "<<mc_iter->second<<endl;
}
*/
