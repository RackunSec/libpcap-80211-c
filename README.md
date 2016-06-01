#Libpcap, 802.11, and C
This is a simple example of code from the upcoming Penetration Testing 802.11 course for WeakNet Academy. This is a simple example of an 802.11 protocol analyzer. This code simply sniffs on a RFMON-enabled device for a beacon when compiled, linked and loaded. Libpcap is an incredible tool for RF entusiasts and programmers alike. My goal for the lesson is to show how simple the code can be for such a tool. 
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
#References
TCPDump: http://www.tcpdump.org/pcap.html<br />
RadioTap: http://www.radiotap.org/
