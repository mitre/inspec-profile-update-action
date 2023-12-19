control 'SV-80621' do
  title 'The HP FlexFabric Switch must enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if the switch enforces approved authorizations for controlling the flow of information between interconnected networks or VLANs in accordance with applicable policy.  This requirement can be met through the use of IP access control lists which are applied to specific interfaces inbound or outbound as show in the following example:

acl number 3001
 rule 1 deny ip source 192.168.3.121 0
 rule 2  permit ip source 192.100.1.0 0.0.0.255 destination 192.200.2.0 0.0.0.255

interface Ten-GigabitEthernet1/0/21
ip address 102.17.17.2 255.255.255.252
packet-filter 3001 inbound

If the switch does not enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy, this is a finding.'
  desc 'fix', 'Configure the switch to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy using ACLs that are applied to the appropriate interfaces.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66131'
  tag rid: 'SV-80621r1_rule'
  tag stig_id: 'HFFS-RT-000022'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-72207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
