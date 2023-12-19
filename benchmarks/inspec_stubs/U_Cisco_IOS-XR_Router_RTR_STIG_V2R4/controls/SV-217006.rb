control 'SV-217006' do
  title 'The Cisco perimeter router must be configured to block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and henceforth must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

In Cisco IOS XR, all IPv4 packets with any header option other than the "source-route" header options are dropped. By default, ipv4 source routing is disabled. Verify that the following command is not configured: ipv4 source-route

If the router is not configured to drop all packets with IP option source routing, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to drop all packets with IP option source routing.

RP/0/0/CPU0:R3(config)#no ipv4 source-route'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18236r288858_chk'
  tag severity: 'medium'
  tag gid: 'V-217006'
  tag rid: 'SV-217006r856461_rule'
  tag stig_id: 'CISC-RT-000350'
  tag gtitle: 'SRG-NET-000205-RTR-000015'
  tag fix_id: 'F-18234r288859_fix'
  tag 'documentable'
  tag legacy: ['SV-105871', 'V-96733']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
