#ifndef SAVE_KEY_VALUE_H
#define SAVE_KEY_VALUE_H
//################### Beacon ###################
struct key_beacon
{
    uint8_t save_bssid[6];
};
struct value_beacon
{
    uint8_t current_channel;
    uint8_t ESSID[32]; //Maximum 32 length //이부분이 문제임
};


//################### Probe Req ###################
struct key_probe_req
{
    uint8_t probe_save_bssid[6];
};
struct value_probe_req
{
    uint8_t src[6];
    uint8_t probe_current_channel;
    uint8_t probe_ESSID[32]; //Maximum 32 length //이부분이 문제임
};


//################### Probe Res ###################
struct key_probe_res
{
    uint8_t probe_save_bssid[6];
};
struct value_probe_res
{
    uint8_t src[6];
    uint8_t probe_current_channel;
    uint8_t probe_ESSID[32]; //Maximum 32 length //이부분이 문제임
};


//################### Qos Data ###################
struct key_QosData
{
    uint8_t Qos_save_BSSID[6];
};
struct value_QosData
{
    uint8_t STA_addr[6];
    uint8_t Dst[6];
};


//################## Reassociation Request ##################
struct key_Reassociation_req
{
     uint8_t Reassociation_req_save_BSSID[6];
};
struct value_Reassociation_req
{
    uint8_t  src_addr[6];
    uint8_t  dst_addr[6];
    uint8_t  Rea_req_ESSID[32];
};


//################## association Request ##################
struct key_Association_res
{
    uint8_t Association_res_save_BSSID[6];
};
struct value_Association_res
{
    uint8_t  dst_addr[6];
    uint8_t  src_addr[6];
    uint8_t  A_req_ESSID[32];
};

#endif // SAVE_KEY_VALUE_H
