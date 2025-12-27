control 'SV-216990' do
  title 'The Cisco perimeter router must be configured to block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and henceforth must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if it will block all packets with IP options.

ip access-list extended EXTERNAL_ACL
 permit tcp any any established
deny   ip any any option any-options
permit …
 …
 …     
 …
deny   ip any any log-input

If the router is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to drop all packets with IP options.

R1(config)#ip access-list extended EXTERNAL_ACL
R1(config-ext-nacl)#15 deny ip any any option any-options'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-18220r287298_chk'
  tag severity: 'medium'
  tag gid: 'V-216990'
  tag rid: 'SV-216990r856207_rule'
  tag stig_id: 'CISC-RT-000350'
  tag gtitle: 'SRG-NET-000205-RTR-000015'
  tag fix_id: 'F-18218r287299_fix'
  tag 'documentable'
  tag legacy: ['SV-105705', 'V-96567']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
