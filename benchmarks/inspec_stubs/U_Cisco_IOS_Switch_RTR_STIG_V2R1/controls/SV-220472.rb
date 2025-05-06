control 'SV-220472' do
  title 'The Cisco perimeter switch must be configured to block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and henceforth must be punted to the switch processor. Hackers who initiate denial-of-service (DoS) attacks on switches commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the switch. The end result is a reduction in the effects of the DoS attack on the switch and on downstream switches.'
  desc 'check', 'Review the switch configuration to determine if it will block all packets with IP options. 

ip access-list extended EXTERNAL_ACL 
 permit tcp any any established 
deny ip any any option any-options 
permit … 
 … 
 … 
 … 
deny ip any any log-input 

If the switch is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the switch to drop all packets with IP options. 

SW1(config)#ip access-list extended EXTERNAL_ACL 
SW1(config-ext-nacl)#15 deny ip any any option any-options'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22187r508489_chk'
  tag severity: 'medium'
  tag gid: 'V-220472'
  tag rid: 'SV-220472r622190_rule'
  tag stig_id: 'CISC-RT-000350'
  tag gtitle: 'SRG-NET-000205-RTR-000015'
  tag fix_id: 'F-22176r508490_fix'
  tag 'documentable'
  tag legacy: ['SV-110743', 'V-101639']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
