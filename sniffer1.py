from scapy.all import *
from threading import Thread
def findCredentials(pkt):
	if pkt.haslayer(TCP):
		raw = pkt.sprintf("%Raw.load%")
		username=re.findall("(?i)username=(.*)&",raw)
		password=re.findall("(?i)password=(.*)&",raw)
		if username:
			print("Found username and password:",str(username[0]),str(password[0]))


def main():
	pkts=rdpcap('creds.pcap')
	for pkt in pkts:
		t=Thread(target=findCredentials(pkt))
		t.start()



if __name__ == '__main__':
	main()