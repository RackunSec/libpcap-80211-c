#Libpcap, 802.11, and C
This is a simple example of code from the upcoming Penetration Testing 802.11 course for WeakNet Academy. This is a simple example of an 802.11 protocol analyzer. This code simply sniffs on a RFMON-enabled device for a beacon when compiled, linked and loaded. Libpcap is an incredible tool for RF entusiasts and programmers alike. My goal for the lesson is to show how simple the code can be for such a tool. <br /><br />
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
##PCAP Functions Used
Below I will cover all of the LibPCAP specific functions used in the 80211sniff.c code.
### pcap_open_live()
This function opens the device for capturing packets. We use it as, ```handle = pcap_open_live(dev, BUFSIZ, 0, 3000, erbuf);``` which has 5 arguments. This function is for creating a handle which we creatively just name ```pcap_t *handle```. ```handle``` will be NULL if an error has occurred while trying to listen on the device. The error will be stored in memory and pointed to by the the ```erbuf``` string pointer. This is why we check for an error and print it if so like so, ```if(handle==NULL){ printf("ERROR: %s\n",erbuf); exit(1); } // was the device ready/readable?```
<ul>
<li>dev - The wireless device.</li>
<li>BUFSIZ - size of buffer or snap length of the handle.</li>
<li>0 - Boolean - promiscous mode or not.</li>
<li>3000 - timeout for reading data in milliseconds.</li>
<li>erbuf - a place to store any error that arises from trying to run the ```pcap_open_live()``` function.</li>
</ul>
### pcap_datalink()
...
### pcap_compile()/pcap_setfilter()
...
### pcap_open_dead()/pcap_dump_open()/pcap_dump()/pcap_close()
...
#Example Output
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
##Tagged Parameters
Tagged parameters are a way of efficiently transmitting data that is of variable length. For instance, the ESSID, or AP name, e.g. "Linksys" or "Free open WiFi", is something that is of variable length. To transmit this data, a tagged parameter can be used. These tagged parameters on my machine (Weakerthan Linux 7) start at the offset of 62 bytes. The tagged parameters are not delimited in any way, so finding the length of the tag is important. They begin with a "tag type" byte, which specifies the type of tag e.g. "RSN information" or "SSID Parameter" and the second byte is the length (in bytes). Consider the example snippet below from the Tagged parameters segment of an 802.11 packet.
```
0000   30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00
0010   00 0f ac 01 28 00
```
The first byte, 30 is hexadecimal for 48, which is for "RSN Information". The second byte, 14 is hexadecimal for 20, which means the data length of the tagged parameter is 20 bytes. The entire tag itself is 22 bytes, but the first 2 bytes are for type and length.
<br /><br />
So to do anything with tagged paremeters, we simply need to programmatically walk through the bytes of the tagged paramters segment of the packet, get the type and length of the parameter for each tag before processing/handling them.

##References
TCPDump: http://www.tcpdump.org/pcap.html<br />
RadioTap: http://www.radiotap.org/<br />
Weakerthan Linux 7: http://www.weaknetlabs.com/p/weakerthan-linux-6.html 
