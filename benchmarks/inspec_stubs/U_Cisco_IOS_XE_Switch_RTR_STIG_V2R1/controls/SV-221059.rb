control 'SV-221059' do
  title 'The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.'
  desc 'When a new source starts transmitting in a PIM Sparse Mode network, the DR will encapsulate the multicast packets into register messages and forward them to the RP using unicast. This process can be taxing on the CPU for both the DR and the RP if the source is running at a high data rate and there are many new sources starting at the same time. This scenario can potentially occur immediately after a network failover. The rate limit for the number of register messages should be set to a relatively low value based on the known number of multicast sources within the multicast domain.'
  desc 'check', 'Review the configuration of the RP to verify that it is rate limiting the number of PIM register messages.

ip pim rp-address 10.2.2.2
ip pim register-rate-limit nn

If the RP is not limiting PIM register messages, this is a finding.'
  desc 'fix', 'Configure the RP to rate limit the number of multicast register messages.

SW2(config)#ip pim register-rate-limit nn'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22774r408971_chk'
  tag severity: 'medium'
  tag gid: 'V-221059'
  tag rid: 'SV-221059r622190_rule'
  tag stig_id: 'CISC-RT-000850'
  tag gtitle: 'SRG-NET-000362-RTR-000121'
  tag fix_id: 'F-22763r408972_fix'
  tag 'documentable'
  tag legacy: ['SV-110939', 'V-101835']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
