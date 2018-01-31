#pragma once
#include <spdlog\spdlog.h> 
#include <iostream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <pcap\pcap.h>
#include <thread>
#include <WinSock2.h>
#include <socketapi.h>
using namespace std;
#define IEEE80211_SUBTYPE_PROBERESP             0x5000
#define IEEE80211_SUBTYPE_BEACON                0x8000
#define IEEE80211_MANAGEMENT_TAG_SSID           0x00
#define IEEE80211_MANAGEMENT_TAG_CHANNEL        0x03
#define IEEE80211_MANAGEMENT_TAG_SUP_DATA_RATE  0x01
#define IEEE80211_MANAGEMENT_TAG_EXT_DATA_RATE  0x32
#pragma(1)


struct flags{
u_int64_t mactime; //TSFT, 0
u_int8_t flags; //1
u_int8_t rate; //2
u_int16_t channel_frequency, channel_flags; //3
u_int8_t hop_set, hop_pattern; //FHSS, 4
int8_t antenna_signal; //5
int8_t antenna_noise; //6
u_int16_t lock_quality; //7
u_int16_t TX_attenuation; //8
u_int16_t db_TX_attenuation; //9
int8_t dBm_TX_power; //10
u_int8_t antenna; //11
u_int8_t db_antenna_signal; //12
u_int8_t db_antenna_noise; //13
u_int16_t rx_flags; //14
//15~18
u_int8_t known, flags, mcs; // MCS, 19
u_int32_t reference_number; //A-MPDU status, 20
u_int16_t flags;
u_int8_t delimiter_CRC_value, reserved;
u_int16_t known; //VHT, 21
u_int8_t flags, bandwidth, mcs_nss[4], coding, group_id;
u_int16_t partial_aid;
u_int64_t timestamp; //timestamp, 22
u_int16_t accuracy;
u_int8_t unit, position, flags;
//23~28
//radiotap namespace, unused, 29
u_int8_t out[3], sub_namespace; //vendor namespace, 30
u_int16_t skip_length;
};




typedef struct ether_addr
{
	u_char addr[6];
}ETHERAddr;

typedef struct ethernet_header
{
	
	struct ether_addr dest[6];
	struct ether_addr source[6];
	u_short type; 
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;


struct radiotap_hdr
{
	uint8_t     revision;
	uint8_t     pad;
	uint16_t    length;
	uint32_t    present_flags;
	uint64_t    macTimestamp;
	uint8_t     flags;
	uint8_t     dataRate;
	uint16_t    channelFrequency;
	uint16_t    channelFlags;
	uint8_t     ssiSignal;
	uint8_t     rxFlags;
	uint8_t     antenna;
};



typedef struct frameCtrl
{
	uint8_t version : 2;
	uint8_t type : 2;
	uint8_t subType : 4;

}FrameCtrl;
struct IEEE80211_hdr
{
	FrameCtrl frameCtrl;
	uint16_t            duration;
	struct ether_addr   dst_addr;
	struct ether_addr   src_addr;
	struct ether_addr   bssid;
	uint8_t FragNum;
	uint8_t sequenceNum;
};

struct IEEE80211_mgt_fixed_param
{
	uint64_t    timestamp;
	uint16_t    beacon_interval;
	uint16_t    capa_info;
};

struct IEEE80211_mgt_pkt
{
	struct radiotap_hdr                 radiotap_hdr;
	struct IEEE80211_hdr                IEEE80211_hdr;
	struct IEEE80211_mgt_fixed_param    IEEE80211_mgt_fixed_param;
};