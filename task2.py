from scapy.all import DNSQR, DNS, IP, UDP, sr1
from scapy.all import *


if __name__=="__main__":

	Qdsec  = DNSQR(qname='www.example.com')
	dns    = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)

	ip  = IP(dst='10.9.0.53', src='10.9.0.1')
	udp = UDP(dport=53, sport=33333, chksum=0)
	request = ip/udp/dns
	send(request, loop=1)

