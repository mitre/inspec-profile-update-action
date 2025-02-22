control 'SV-216998' do
  title 'The Cisco perimeter router must be configured to block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and henceforth must be punted to the router processor. Hackers who initiate denial of service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
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
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-18228r288156_chk'
  tag severity: 'medium'
  tag gid: 'V-216998'
  tag rid: 'SV-216998r531086_rule'
  tag stig_id: 'CISC-RT-000350'
  tag gtitle: 'SRG-NET-000205-RTR-000015'
  tag fix_id: 'F-18226r288157_fix'
  tag 'documentable'
  tag legacy: ['V-96919', 'SV-106057']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
