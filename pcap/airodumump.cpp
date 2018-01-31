#define SPDLOG_TRACE_ON
#define SPDLOG_DEBUG_ON
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

// header 파일 중 제일 먼저 적어주어야 함! 안그러면 에러남.
#include <spdlog\spdlog.h> 
#include <iostream>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <pcap\pcap.h>
#include <thread>
#include <WinSock2.h>
#include <socketapi.h>


namespace spd = spdlog;
using namespace std;


int main(int argc, char* argv[])
{
	
		
	auto console = spd::stdout_color_mt("console");
	if (argc != 2)
	{
		console->error("you must input two parameter");
		cout << "usage : <interface> <name>" << endl;
		exit(1);
	}
	char* _interface = argv[1];
	cout << "interface name =  " << _interface << endl;

	char* errbuf;
	
	//typedef struct pcap pcap_t;
	pcap_t *handle;
	
	/*
	name : pcap_create

	parameter:
	1. interface
	2. errbuf

	return : pcap_t *

	function : create a live capture handle  
	*/
	if (!(handle = pcap_create(_interface, errbuf))) // handle == NULL
	{
		console->error("pcap_create error");
		exit(1);
	}
	console->info("pcap_create succeed");
	//struct pcap_pkthdr {
	//	struct timeval ts;	/* time stamp */
	//	bpf_u_int32 caplen;	/* length of portion present */
	//	bpf_u_int32 len;	/* length this packet (off wire) */
	//};

	if (pcap_set_promisc(handle, PROMISCUOUS)) // != NULL
	{
		console->error("pcap_set_promisc : error");
		//LOG(FATAL) << "pcap_set_promisc : failed";
		return -1;
	}
	console->info("pcap_set_promisc : succeed");
	
	/*
	name : pcap_set_rfmon
	parameter:
	1. pcap_t *
	2. non-zero(monitor mode) , zero(manage mode)
	function:  set monitor mode for a not-yet-activated capture handle  
	*/
	if (pcap_set_rfmon(handle, 1) != 0)
	{

		console->error("pcap_set_rfmon : error");
		return -1;
	}

	console->info("pcap_set_rfmon : succeed");
	/*
	name : pcap_set_snaplen

	parameter :
	1. pcap_t *
	2. size
	function:
	sets the snapshot length to be used on a capture handle
	*/
	if (pcap_set_snaplen(handle, BUFSIZ))
	{
		console->error("pcap_set_snaplen : error");
		return -1;
	}
	console->info("pcap_set_snaplen : succeed");


	/*
	name: pcap_set_timeout
	parameter:
	1. pcap_t *
	2. ms(time)
	function:
	set  the packet buffer timeout for a not-yet-activated capture handle
	return:
	success(0)
	PCAP_ERROR_ACTIVATED
	*/
	if (pcap_set_timeout(handle, 1))
	{
		console->error("pcap_set_timeout");
		return -1;
	}
	console->info("pcap_set_timeout : succeed");

	/*
	name : pcap_activate
	parameter:
	1. pcap_t *
	function:
	activate a packet capture handle to look at packets on the network, 
	with the options that were set on the handle being in effect.
	return :
	succeess(0)
	warning(postive non-zero)양수
	error(negative non-zero)음수
	*/
	if (pcap_activate(handle) != 0)
	{
		console->error("pcap_activate : error");
		return -1;
	}
	console->error("pcap_activate");


	struct pcap_pkthdr*	pkthdr;
	//typedef unsigned char   u_char;
	const u_char* packet;
	int res;

	/*
	name : pcap_next_ex
	parameter:
	1. pcap_t *
	2. pcap_pkthdr
	3. const char *

	function: read the next pcaket from pcap_t
	성공 시 pcap_pkthdr
	return : 
	success(1)
	time expired(0)
	error(-1)
	no_savefile(-2)
	*/
	while (res = pcap_next_ex(handle, &pkthdr, &packet)) {
		if (res == 1)
			;
		else if (!res) // !=0
			console->info("pcap_next_ex : timeout");
		else if (res == -1)
			console->error("pcap_next_ex : Error");
		else if (res == -2)
			console->warn("pcap_next_ex : no_savefile");
		else
			console->warn("pcap_next_ex : (EOF)알 수 없는 반환값");
	}


	
	return 0;
}

 

