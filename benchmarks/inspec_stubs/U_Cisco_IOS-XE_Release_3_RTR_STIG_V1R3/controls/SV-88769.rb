control 'SV-88769' do
  title 'The Cisco IOS XE router must enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'Review the Cisco IOS XE router configuration.

Verify that the external interface blocks inbound traffic with a source IP address belonging to the internal network. The configuration should look similar to the example below where the private IP address space is 1.1.1.0/24:

interface FastEthernet 0/0
description  NIPRNet link
ip address x.x.x.x 255.255.255.0
ip access-group INGRESS_ACL in
...

ip access-list extended INGRESS_ACL
deny ip 1.1.1.0 0.0.0.255 any log
...

If the external interface of the Cisco IOS XE router has not been configured to block all inbound packets with a source IP address belonging to the private network, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to block all inbound packets with a source IP address belonging to the private network. The configuration would look similar to the example below:

interface FastEthernet 0/0
description  NIPRNet link
ip address x.x.x.x 255.255.255.0
ip access-group INGRESS_ACL in
...

ip access-list extended INGRESS_ACL
deny ip 1.1.1.0 0.0.0.255 any log
...'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74181r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74095'
  tag rid: 'SV-88769r2_rule'
  tag stig_id: 'CISR-RT-000001'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-80637r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
