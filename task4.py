from scapy.all import DNSQR, DNS, IP, UDP, sr1
from scapy.all import *


if __name__=="__main__":

	
	name = 'twysw.example.com'
	Qdsec = DNSQR(qname=name)
	dns = DNS(id=0xAAAA, qr=0,qdcount=1, ancount=0, nscount=0, arcount=0,qd=Qdsec)

	ip    = IP(dst='10.9.0.53', src='10.9.0.1')
	udp   = UDP(dport=53, sport=33333, chksum=0) 
	pkt = ip/udp/dns 
	
	with open('ip_req.bin','wb') as f:
		f.write(bytes(pkt))
