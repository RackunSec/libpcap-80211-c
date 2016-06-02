#Libpcap, 802.11, and C
This is a simple example of code from the upcoming Penetration Testing 802.11 course for WeakNet Academy. This is a simple example of an 802.11 protocol analyzer. This code simply sniffs on a RFMON-enabled device for a beacon when compiled, linked and loaded. Libpcap is an incredible tool for RF entusiasts and programmers alike. My goal for the lesson is to show how simple the code can be for such a tool. <br /><br />
The code is broken up into three parts, ```main()``` the entry point of the application, ```pcapHandler()``` the handler that gets called for every packet found, and ```usage()``` which simply just tells the user how to use the application. 
#Example Output
Below is a simple output taken from my VMWare station.<br />
```
root@wt7-dev:~/Programming/c/802Sniff# gcc 802sniff.c -lpcap -o 802sniff -ggdb
root@wt7-dev:~/Programming/c/802Sniff# ./802sniff 
Usage: ./80211sniff deviceName
root@wt7-dev:~/Programming/c/802Sniff# ./802sniff wrong-dev
ERROR: wrong-dev: SIOCETHTOOL(ETHTOOL_GET_TS_INFO) ioctl failed: No such device
root@wt7-dev:~/Programming/c/802Sniff# ./802sniff wlan0mon
ESSID string: NETGEAR61
BSSID string: DC:EF:09:A0:4B:3A
root@wt7-dev:~/Programming/c/802Sniff#
```
#Tagged Parameters
Tagged parameters are a way of efficiently transmitting data that is of variable length. For instance, the ESSID, or AP name, e.g. "Linksys" or "Free open WiFi", is something that is of variable length. To transmit this data, a tagged parameter can be used. These tagged parameters on my machine (Weakerthan Linux 7) start at the offset of 62 bytes. The tagged parameters are not delimited in any way, so finding the length of the tag is important. They begin with a "tag type" byte, which specifies the type of tag e.g. "RSN information" or "SSID Parameter" and the second byte is the length (in bytes). Consider the example snippet below from the Tagged parameters segment of an 802.11 packet.
```
0000   30 14 01 00 00 0f ac 04 01 00 00 0f ac 04 01 00
0010   00 0f ac 01 28 00
```
The first byte, 30 is hexadecimal for 48, which is for "RSN Information". The second byte, 14 is hexadecimal for 20, which means the data length of the tagged parameter is 20 bytes. The entire tag itself is 22 bytes, but the first 2 bytes are for type and length.
<br /><br />
So to do anything with tagged paremeters, we simply need to programmatically walk through the bytes of the tagged paramters segment of the packet, get the type and length of the parameter for each tag before processing/handling them.

#References
TCPDump: http://www.tcpdump.org/pcap.html<br />
RadioTap: http://www.radiotap.org/
