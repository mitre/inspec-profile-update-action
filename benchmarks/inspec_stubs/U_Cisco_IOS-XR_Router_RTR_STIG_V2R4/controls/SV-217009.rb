control 'SV-217009' do
  title 'The Cisco PE router must be configured to ignore or block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and therefore must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'In Cisco IOS XR, all IPv4 packets with any header option other than the "source-route" header options are dropped. By default, ipv4 source routing is disabled. 

Verify that the following command is not configured:

 ipv4 source-route

If the router is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the router to drop all packets with ipv4 source-route as shown below.

RP/0/0/CPU0:R3(config)#no ipv4 source-route'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18239r288867_chk'
  tag severity: 'medium'
  tag gid: 'V-217009'
  tag rid: 'SV-217009r856464_rule'
  tag stig_id: 'CISC-RT-000750'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-18237r288868_fix'
  tag 'documentable'
  tag legacy: ['SV-105951', 'V-96813']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
