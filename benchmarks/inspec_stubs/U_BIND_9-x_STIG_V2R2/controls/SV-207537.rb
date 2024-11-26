control 'SV-207537' do
  title 'The host running a BIND 9.x implementation must use a dedicated management interface in order to separate management traffic from DNS specific traffic.'
  desc 'Providing Out-Of-Band (OOB) management is the best first step in any management strategy. No production traffic resides on an out-of-band network. The biggest advantage to implementation of an OOB network is providing support and maintenance to the network that has become degraded or compromised. During an outage or degradation period the in band management link may not be available.'
  desc 'check', 'Verify that the BIND 9.x server is configured to use a dedicated management interface:

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

If one of the interfaces listed is not dedicated to only process management traffic, this is a finding.'
  desc 'fix', 'On the host machine, configure an interface that is dedicated to management traffic.

Restart the host machine.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7792r283665_chk'
  tag severity: 'medium'
  tag gid: 'V-207537'
  tag rid: 'SV-207537r612253_rule'
  tag stig_id: 'BIND-9X-001005'
  tag gtitle: 'SRG-APP-000516-DNS-000109'
  tag fix_id: 'F-7792r283666_fix'
  tag 'documentable'
  tag legacy: ['SV-86997', 'V-72373']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
