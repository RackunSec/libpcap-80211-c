/* GNU 2016
 *
 * 80211 MGMT Frame Simple Sniffer written in C by
 * Douglas Berdeaux, 2016 - weaknetlabs@gmail.com
 *
 * Listens for a beacon and prints data if one found
 * exits if not.
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
		pcap_dispatch(handle, 1, pcapHandler, NULL); // dispatch to call upon packet 
		return 0;
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
	const u_char *bssid; // a place to put our BSSID \ these are bytes
	const u_char *essid; // a place to put our ESSID / from the packet
	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len; // 26 bytes on my machine
	if(packet[offset]==0x80){ // 0x80 is 128 in dec. It is a Beacon MGMT frame
		bssid = packet + 36; // store the BSSID/AP MAC addr
		essid = packet + 64; // store the ESSID/Router name too
		char *ssid = malloc(63); // 63 byte limit
		unsigned int i = 0; // used in loop below:
		while(essid[i] > 0x1){ // uncomment these to see each byte individually:
			//printf ("hex byte: %x\n",essid[i]); // view byte
			//printf ("hex char: %c\n",essid[i]); // view ASCII
			ssid[i] = essid[i]; // store the ESSID bytes in *ssid
			i++; // POSTFIX
		}
		ssid[i] = '\0'; // terminate the string
		printf("ESSID string: %s\n", ssid); // print the stored ESSID bytes
		printf("BSSID string: %02X:%02X:%02X:%02X:%02X:%02X\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
	}
	return;
}
// print how to use the application:
void usage(void){ // display how to use application
	fprintf(stderr,"Usage: ./80211sniff deviceName\n"); // function in stdio.h
	return; // print to /dev/stderr
}
