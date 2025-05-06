control 'SV-251394' do
  title 'Multicast register messages must be rate limited per each source-group (S, G) entry.'
  desc 'When a new source starts transmitting in a PIM Sparse Mode network, the DR will encapsulate the multicast packets into register messages and forward them to the Rendezvous Point (RP) using unicast. This process can be taxing on the CPU for both the DR and the RP if the source is running at a high data rate and there are many new sources starting at the same time. This scenario can potentially occur immediately after a network failover. The rate limit for the number of register messages should be set to a relatively low value based on the known number of multicast sources within the multicast domain.'
  desc 'check', 'Review the configuration of the DR to verify that it is rate limiting the number of multicast register messages.

If the DR is not limiting multicast register messages, this is a finding.

The following is a PIM sparse mode configuration example that limits the number of register messages for each (S, G) multicast entry to 10 per second.

ip multicast-routing
! 
interface FastEthernet 0/0 
description link to core
ip address 192.168.123.2 255.255.255.0
ip pim sparse-mode 
! 
interface FastEthernet 0/1
description User LAN
ip address 192.168.122.1 255.255.255.0
ip pim sparse-mode 
!
ip pim rp-address 1.1.1.1
ip pim register-rate 10'
  desc 'fix', 'Configure the Designated Router (DR) to rate limit the number of multicast register messages it will allow for each (S, G) entry.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54829r806135_chk'
  tag severity: 'medium'
  tag gid: 'V-251394'
  tag rid: 'SV-251394r806137_rule'
  tag stig_id: 'NET2012'
  tag gtitle: 'NET2012'
  tag fix_id: 'F-54782r806136_fix'
  tag 'documentable'
  tag legacy: ['V-66379', 'SV-80869']
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']
end
