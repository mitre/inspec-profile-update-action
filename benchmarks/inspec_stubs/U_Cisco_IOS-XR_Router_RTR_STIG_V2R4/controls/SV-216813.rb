control 'SV-216813' do
  title 'The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.'
  desc 'When a new source starts transmitting in a PIM Sparse Mode network, the Designated Router (DR) will encapsulate the multicast packets into register messages and forward them to the RP using unicast. 

This process can be taxing on the CPU for both the DR and the RP if the source is running at a high data rate and there are many new sources starting at the same time. This scenario can potentially occur immediately after a network failover. 

The rate limit for the number of register messages should be set to a relatively low value based on the known number of multicast sources within the multicast domain.'
  desc 'check', 'Review the configuration of the RP to verify that it is  limiting the number of PIM register states as shown in the example. 

router pim
 address-family ipv4
  allow-rp group-list FILTER_PIM_JOINS
  rp-address 10.2.2.2
  accept-register PIM_REGISTER_FILTER
  maximum register-states 250

Note: The maximum register-states command is used to set an upper limit for PIM register states. When the limit is reached, PIM discontinues route creation from PIM register messages. If not configured, the default is 2000 which would be an overage for a small to average size multicast deployment. 

If the RP is not limiting PIM register states, this is a finding.'
  desc 'fix', 'Configure the RP to rate limit the number of multicast register states.

RP/0/0/CPU0:R2(config)#router pim
RP/0/0/CPU0:R2(config-pim)#address-family ipv4
RP/0/0/CPU0:R2(config-pim-default-ipv4)#maximum register-states 250
RP/0/0/CPU0:R2(config-pim-default-ipv4)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18045r288813_chk'
  tag severity: 'medium'
  tag gid: 'V-216813'
  tag rid: 'SV-216813r856450_rule'
  tag stig_id: 'CISC-RT-000850'
  tag gtitle: 'SRG-NET-000362-RTR-000121'
  tag fix_id: 'F-18043r288814_fix'
  tag 'documentable'
  tag legacy: ['SV-105971', 'V-96833']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
