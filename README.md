
Implementation of full cone SNAT. Currently only UDP is supported and actions for other protos are like MASQUERADE.

Assume eth0 is external interface:

iptables -t nat -A POSTROUTING -o eth0 -j FULLCONENAT #same as MASQUERADE  
iptables -t nat -A PREROUTING -i eth0 -j FULLCONENAT
