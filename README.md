# LibPCAP, 802.11, and C
This is a simple example of home-brew 802.11 protocol analyzer code is from the upcoming Penetration Testing 802.11 course for WeakNet Academy. This code simply sniffs on a RFMON-enabled device for a beacon when compiled, linked and loaded. Libpcap is an incredible tool for RF enthusiasts and programmers alike. My goal for the lesson is to show how simple the code can be for such a tool. <br /><br />
The code is broken up into three parts, ```main()``` the entry point of the application, ```pcapHandler()``` the handler that gets called for every packet found, and ```usage()``` which simply just tells the user how to use the application.
### main()
This is the main entry point for any C application. In this function, we set the application up to start listening on the specified wireless device for a packet. We create a packet capture filter using the TCPDump/LibPCAP filter syntax after calling ```pcap_open_live()``` and call ```pcap_dispatch()```.  
### pcapHandler()
This function is called by the ```pcap_dispatch()``` function for each packet found. In our case, we only have a single packet to process. ```pcap_loop()``` can be easily substituted for this function which will loop through packets indefinitely.
### usage()
This function simply prints the usage for the application. It is called when the argument count to the application is too low using the following syntax.
```
if(argc >= 2){ // argument to contain a wireless device name
 // arguments OK. do stuff here
}else{ // no argument, display usage:
	usage();
	return 1;
}
```
## PCAP Functions Used
Below I will cover all of the LibPCAP specific functions used in the 80211sniff.c code.
### pcap_open_live()
This function opens the device for capturing packets. We use it as, ```handle = pcap_open_live(dev, BUFSIZ, 0, 3000, erbuf);``` which has 5 arguments. This function is for creating a handle which we creatively just name ```pcap_t *handle```. ```handle``` will be NULL if an error has occurred while trying to listen on the device. The error will be stored in memory and pointed to by the the ```erbuf``` string pointer. This is why we check for an error and print it if so like so, ```if(handle==NULL){ printf("ERROR: %s\n",erbuf); exit(1); } // was the device ready/readable?```

* **dev** - The wireless device.</li>
* **BUFSIZ** - size of buffer or snap length of the handle.</li>
* **0** - Boolean - promiscous mode or not.</li>
* **3000** - timeout for reading data in milliseconds.</li>
* **erbuf** - a place to store any error that arises from trying to run the ```pcap_open_live()``` function.</li>

### pcap_datalink()
This function returns an integer when passed the handle, whic is it's only argument. In our code, we use it as ```printf("Type: %d\n",pcap_datalink(handle));``` What is printed is the link-layer header type for the packet received. In our case, 127 is the link-layer header type, which refers to the 802.11 IEEE RadioTap header: ```LINKTYPE_IEEE802_11_RADIOTAP	127	DLT_IEEE802_11_RADIO```. Uncomment the call to ```printf()``` to verify before compiling the code.
### pcap_compile()/pcap_setfilter()
The ```pcap_compile()``` function is used for creating a Berkley Filter Program, BFP, TCPDump filter. We use simple strings with specific syntax to filter out only the packet types that we want. In our case, we want a 802.11 Beacon packet. These packets are 802.11 management frames with a subtype value of 8, which in little endian format is represented as the byte: ```80```. The string that we use to get the beacon is ```type mgt subtype beacon``` and is defined to the pointer ```char *filter``` as ```char *filter = "type mgt subtype beacon"; // beacon frame WLAN```. Using BPF is much more efficient that simply checking the values of the packet for type and subtype and should be used. For more information on TCPDump filters, check out the references section below. The arguments to ```pcap_compile()``` are as follows,
* **handle** - the opened handle to the PCAP session created by ```pcap_open_live()```.
* **bpf program** - a dereferenced pointer to a struct of the type bpf_program as we created with ```struct bpf_program fp; ```.
* **filter** - our string object, ```filter``` that contains the BPF filter syntax as described above.
* **0** - Boolean for optimization
* **netp** - an object of type ```bpf_u_int32``` which is the netmask of the device. In our case, we don't have a netmask since our device is in RFMON mode.
This sub routine will return a -1 if it fails, thus we have a test as ```if(pcap_compile(handle,&fp,filter,0,netp)==-1) // -1 means failed``` which will exit the application by calling ```exit(1)``` if true.

### pcap_open_dead()/pcap_dump_open()/pcap_dump()/pcap_close()
These functions are for writing our captured packet to a file. The first, ```open_pcap_dead()``` opens a faux handle to a ```pcap_t``` session for writing. This does not open a file on disk, but a fake capture session. We pass to this function two arguments,
* **DLT_IEEE802_11_RADIO** - data link-type constant as defined by ```/usr/include/pcap/bpf.h``` as ```#define DLT_IEEE802_11_RADIO 127  802.11 plus radiotap radio header```
* **BUFSIZ** - snap length constant as defined by ```/usr/include/stdio.h``` as ```#define BUFSIZ _IO_BUFSIZ```.

The second, ```pcap_dump_open()``` opens the actual file on disk to write the packet to that is "captured" by the faux handle created by ```pcap_open_dead()```. In our code we call it with 2 arguments,
* **fileHandle** - the ```pcap_t``` handle open to open the PCAP session.
* **outputFileName** - the string of bytes that defines our file name on disk, in our case ```./output.cap```. This can be offloaded to an argument in ```argv[]```, but please remember to add it to the ```usage()``` subroutine.<br />

The third subroutine, ```pcap_dump()```, writes the packet ot the file that is opened by ```pcap_dump_open()```. It takes three arguments, 
* **(u_char *) outputFile** - the ```pcap_dump_t``` object.
* **header** - the ```const struct pcap_pkthdr``` object that we defined at the interface to ```pcapHandler()``` and is passed by ```pcap_dispatch()```.
* **packet** - the ```const u_char *packet``` passed to the ```pcapHandler()``` function and is also passed by the ```pcap_dispatch()``` function.

Finally, our last function is the ```pcap_close()``` fucntion which simply closes the file descriptor argument, ```fileHandle```. Without closing the file descriptor we could have corrupted data left in the ```./output.cap``` file after our capture session.
# Example Output
Below is a simple output taken from my VMWare station with Weakerthan Linux 7 and an ALFA 802.11 USB WiFi adapter.<br />
```
root@wt7-dev:~/Programming/c/802Sniff# ./802sniff 
Usage: ./80211sniff deviceName
root@wt7-dev:~/Programming/c/802Sniff# ./802sniff wrong-device
ERROR: wrong-device: SIOCETHTOOL(ETHTOOL_GET_TS_INFO) ioctl failed: No such device
root@wt7-dev:~/Programming/c/802Sniff# gcc 802sniff.c -lpcap -o 802sniff -ggdb
root@wt7-dev:~/Programming/c/802Sniff# ./802sniff wlan0mon
RSSI: -39 dBm
AP Frequency: 2457Mhz
ESSID length: 16 bytes.
ESSID string: Dell M900HD 55fa
BSSID string: 24:FD:52:78:55:FA
root@wt7-dev:~/Programming/c/802Sniff# 
```
## Tagged Parameters
Tagged parameters are a way of efficiently transmitting data that is of variable length. For instance, the ESSID, or AP name, e.g. "Linksys" or "Free open WiFi", is something that is of variable length. To transmit this data, a tagged parameter can be used. These tagged parameters on my machine (Weakerthan Linux 7) start at the offset of 62 bytes. The tagged parameters are not delimited in any way, so finding the length of the tag is important. They begin with a "tag type" byte, which specifies the type of tag e.g. "RSN information" or "SSID Parameter" and the second byte is the length (in bytes). Consider the example snippet below from the Tagged parameters segment of an 802.11 packet.
```
30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00
00 0f ac 01 28 00
```
Remember that each byte is simply a number ranging from 00 to ff. To make sens of the numbers, we need to figure out what kind of tag-type we are working with. The first byte in the snippet above, which is the tag-type, 30 is hexadecimal for 48, which is for "RSN Information". The second byte, 14 is hexadecimal for 20, which means the data length of the tagged parameter is 20 bytes. The entire tag itself is 22 bytes, but the first 2 bytes are for type and length.
<br /><br />
So to do anything with tagged paremeters, we simply need to programmatically walk through the bytes of the tagged paramters segment of the packet, get the type and length of the parameter for each tag before processing/handling them. Without tagged parameters, we would need to send packets with lots of unnecessary padding. Consider the fact that an ESSID can be 32 characters in length. If the ESSID were set to a 9 character string, that would require sending 32 - 9 = 23 padding characters! This is one reason why tagged parameters are more efficient when transmitting data.

##  Compiling
Compiling an application which uses libraries requires a few special parameters, in our case we simply specify that we want to use libpcap as so,

```root@wt7:~ #gcc 80211sniff.c -lpcap -o 80211sniff -ggdb```.

# References
TCPDump: http://www.tcpdump.org/pcap.html<br />
TCPDump Link-Layer Header Info: http://www.tcpdump.org/linktypes.html<br />
Berkley Filter Program, TCPDump filters: http://biot.com/capstats/bpf.html<br />
RadioTap: http://www.radiotap.org/<br />
Weakerthan Linux 7: http://www.weaknetlabs.com/p/weakerthan-linux-6.html
