control 'SV-207538' do
  title 'The host running a BIND 9.x implementation must use an interface that is configured to process only DNS traffic.'
  desc 'Configuring hosts that run a BIND 9.X implementation to only accept DNS traffic on a DNS interface allows a system to be configured to segregate DNS traffic from all other host traffic.

The TCP/IP stack in DNS hosts (stub resolver, caching/resolving/recursive name server, authoritative name server, etc.) could be subjected to packet flooding attacks (such as SYNC and smurf), resulting in disruption of communication. 

The use of a dedicated interface for DNS traffic allows for these threats to be mitigated by creating a means to limit what types of traffic can be processed using a host based firewall solution.'
  desc 'check', 'Verify that the BIND 9.x server is configured to use an interface that is configured to process only DNS traffic.

# ifconfig -a
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
inet 10.0.1.252 netmask 255.255.255.0 broadcast 10.0.1.255
inet6 fd80::21c:d8ff:fab7:1dba prefixlen 64 scopeid 0x20<link>
ether 00:1a:b8:d7:1a:bf txqueuelen 1000 (Ethernet)
RX packets 2295379 bytes 220126493 (209.9 MiB)
RX errors 0 dropped 31 overruns 0 frame 0
TX packets 70507 bytes 12284940 (11.7 MiB)
TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1458
inet 10.0.0.5 netmask 255.255.255.0 broadcast 10.0.0.255
inet6 fe81::21c:a8bf:fad7:1dca prefixlen 64 scopeid 0x20<link>
ether 00:1d:d8:b5:1c:dd txqueuelen 1000 (Ethernet)
RX packets 39090 bytes 4196802 (4.0 MiB)
RX errors 0 dropped 0 overruns 0 frame 0
TX packets 93250 bytes 18614094 (17.7 MiB)
TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0

If one of the interfaces listed is not dedicated to only process DNS traffic, this is a finding.'
  desc 'fix', 'On the host machine, configure an interface to only process DNS traffic.

Restart the host machine.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7793r283668_chk'
  tag severity: 'medium'
  tag gid: 'V-207538'
  tag rid: 'SV-207538r612253_rule'
  tag stig_id: 'BIND-9X-001006'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-7793r283669_fix'
  tag 'documentable'
  tag legacy: ['SV-86999', 'V-72375']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
