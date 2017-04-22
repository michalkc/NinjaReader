/*PROJEKT OINS*/

/*STEGANOGRAFIA*/

//Michal Kocon
//Mateusz Chomiczewski

#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

#include "windivert.h"

#define MAXBUF  0xFFFF


void getHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header, UINT payload_len);
static DWORD passthru(LPVOID arg);

int __cdecl main(int argc, char **argv){
	int num_threads = 1;
	HANDLE handle, thread;

	handle = WinDivertOpen(
		"inbound && "              // inbound traffic
		"ip && "                    // Only IPv4
									//	"tcp.SrcPort == 8000 &&"		// port 8000
		"tcp.SrcPort == 8000",		// port 8000
									//	"tcp.PayloadLength > 0",    // TCP data packets only
		WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF //dont drop packets, just sniff them
	);
	if (handle == INVALID_HANDLE_VALUE){
		std::cerr << "error: failed to open the WinDivert device: " << GetLastError() << std::endl;
		exit(EXIT_FAILURE);
	}

	// Start the threads
	for (int i = 1; i < num_threads; i++){
		thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)passthru,
			(LPVOID)handle, 0, NULL);
		if (thread == NULL){
			std::cerr << "error: failed to start a thread" << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	// Main thread:
	passthru((LPVOID)handle);

	return 0;
}

static DWORD passthru(LPVOID arg){
	unsigned char packet[MAXBUF];
	UINT packet_len, payload_len;
	WINDIVERT_ADDRESS addr;
	HANDLE handle = (HANDLE)arg;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;

	bool addr_initialized = false;
	UINT32 src_addr;
	// Main loop:
	while (true){
		// Read a matching packet.
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)){
			std::cerr << "Message read error: " << GetLastError() << std::endl;
			continue;
		}

		WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, &tcp_header, NULL, NULL, &payload_len);
		if (!addr_initialized)
			src_addr = ip_header->SrcAddr; //get 1st connected addr as hacked host
		//if (ip_header->SrcAddr == src_addr)
			getHiddenMessage(ip_header, tcp_header, payload_len);
	}
}
//reads hidden message in tcp/ip packet
void getHiddenMessage(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header, UINT payload_len) {
	static unsigned char byte_to_write = 0;
	static int bit_num = 8; // bit to read
	static std::ofstream message;
	static unsigned char id_last = 0;

	if (bit_num == 8) { //open file on first use
		if (!message.is_open()) {
			std::string filename;
			int file_num = 0;
			while(true)  { //check if file exists
				filename = "hidden_message" + std::to_string(file_num) + ".txt";
				if (std::ifstream(filename))
					++file_num;
				else 
					break;
				
			}

			filename = "hidden_message" + std::to_string(file_num) + ".txt";
			message.open(filename, std::ios::out | std::ios::binary);
		}
		else { // if 8 bits were read, write whole byte to file and stdin
			message << byte_to_write;
			//message.flush();
			std::cout <<byte_to_write;
			bit_num = 0;
			byte_to_write = 0;
		}
	}
	unsigned char* byte = reinterpret_cast<unsigned char*>(&(ip_header->Id));
	if (payload_len > 0 && bit_num < 8) { //hidden message is present only when the frame contains payload
		unsigned char diff = byte[1] - id_last;
		if(diff == 2) //if id jumped by 2, bit is set to 1
			byte_to_write += (0x01 << bit_num);
		++bit_num;
	}
	id_last = byte[1];
}
