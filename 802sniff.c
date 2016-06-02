/* GNU 2016
 *
 * 80211 MGMT Frame Simple Sniffer written in C by
 * Douglas Berdeaux, 2016 - weaknetlabs@gmail.com
 *
 * Listens for a beacon and prints data if one found
 * exits if not.
 *
 * Version 1.1
 *
 */
#include<stdio.h> // for simple IO
#include<stdlib.h> // for malloc();
#include<pcap.h> // for all PCAP functions
#include<netinet/in.h> // for the uint8_t
void usage(void); // function prototypes
void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
// entry point for loader/app:
int main(int argc, char ** argv){ // main function
	if(argc >= 2){ // argument to contain a wireless device name
		int offset = 0;
		char *erbuf; // for errors (required)
		char *dev; // place to store device name
	        dev = argv[1]; // get wlan device from command line
		pcap_t *handle;
		// printf("%s\n",pcap_lib_version()); // DEBUG
		handle = pcap_open_live(dev, BUFSIZ, 0, 3000, erbuf);
		if(handle==NULL){ printf("ERROR: %s\n",erbuf); exit(1); } // was the device ready/readable?
		// printf("Type: %d\n",pcap_datalink(handle)); // DEBUG
		
		// Create a filter "program"
		char *filter = "type mgt subtype beacon"; // beacon frame WLAN
		struct bpf_program fp; 
		bpf_u_int32 netp; // Berkley Packet Filter (same as u_int32_t i believe)
		if(pcap_compile(handle,&fp,filter,0,netp)==-1) // -1 means failed
			fprintf(stderr,"Error compiling Libpcap filter, %s\n",filter);
		if(pcap_setfilter(handle,&fp)==-1) // -1 means failed - but we don't exit(1)
			fprintf(stderr,"Error setting Libpcap filter, %s\n",filter); // same as above

		// finally, we call the dispatch:
		pcap_dispatch(handle, 1, pcapHandler, NULL); // dispatch to call upon packet 
	
		return 0; // good bye main()!
	}else{ // no argument, display usage:
		usage();
		return 1;
	}
}
// Packet handler:
void pcapHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	// This struct is the RadioTap header: https://radiotap.org
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};
	// These are placeholders for offset values:
	const u_char *bssid; // a place to put our BSSID \ these are bytes
	const u_char *essid; // a place to put our ESSID / from the packet
	const u_char *essidLen;
	const u_char *channel; // the frequency (in Mhz) of the AP Radio
	const u_char *rssi; // received signal strength
	const u_char *akm; // Auth Key Mgmt 00-0f-ac-01 == EAP, 00-0f-ac-02 == PSK

	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len; // 26 bytes on my machine
	//if(packet[offset]==0x80){ // 0x80 is 128 in dec. It is a Beacon MGMT frame // REMOVED for BPF syntax
	bssid = packet + 42; // store the BSSID/AP MAC addr, 36 byte offset is transmitter address
	essid = packet + 64; // store the ESSID/Router name too
	essidLen = packet + 63; // store the ESSID length // this can be used to avoid looping bytes until >0x1 as below
	rssi = packet + 22; // this is hex and this value is subtracted from 256 to get -X dbm.
	signed int rssiDbm = rssi[0] - 256;
	channel = packet + 18; // channel in little endian format (2 bytes)
	int channelFreq = channel[1] * 256 + channel[0]; // a little bit of math, remember little endian
	// 87 byte offset contains the "channel number" as per 802.11, e.g. 2412 = "channel 11"
	char *ssid = malloc(63); // 63 byte limit
	unsigned int i = 0; // used in loop below:
	while(essid[i] > 0x1){ // uncomment these to see each byte individually:
		//printf ("hex byte: %x\n",essid[i]); // view byte
		//printf ("hex char: %c\n",essid[i]); // view ASCII
		ssid[i] = essid[i]; // store the ESSID bytes in *ssid
		i++; // POSTFIX
	}
	ssid[i] = '\0'; // terminate the string
	fprintf(stdout,"RSSI: %d dBm\n",rssiDbm);
	fprintf(stdout,"AP Frequency: %iMhz\n",channelFreq);
	fprintf(stdout,"ESSID length: %i bytes.\n",essidLen[0]);
	fprintf(stdout,"ESSID string: %s\n", ssid); // print the stored ESSID bytes
	fprintf(stdout,"BSSID string: %02X:%02X:%02X:%02X:%02X:%02X\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
	//} // REMOVED for BPF syntax
	
	// Let's write the beacon to a file:
	pcap_dumper_t *outputFile;
	pcap_t *fileHandle;
	char *outputFileName = "output.cap";
	fileHandle = pcap_open_dead(DLT_IEEE802_11_RADIO, BUFSIZ);
	outputFile = pcap_dump_open(fileHandle,outputFileName);
	pcap_dump((u_char *) outputFile,header, packet);
	pcap_close(fileHandle);

	return;
}
// print how to use the application:
void usage(void){ // display how to use application
	fprintf(stderr,"Usage: ./80211sniff deviceName\n"); // function in stdio.h
	return; // print to /dev/stderr
}
