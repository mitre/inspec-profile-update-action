control 'SV-88815' do
  title 'The Cisco IOS XE router must only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an ACL (which is a firewall function) or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering, but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

Traffic can be restricted directly by an ACL (which is a firewall function), or by Policy Routing. This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if the router only allows incoming communications from authorized sources to be routed to authorized destinations.

The configuration should look similar to the following example:

interface GigabitEthernet 0/0/1
description NIPRNet link
ip address x.x.x.x 255.255.255.0
ip access-group Authorized_Sources_ACL in
...

ip access-list extended Authorized_Sources_ACL
deny ip 1.1.1.0 0.0.0.255 any log
...

If the Cisco IOS XE router does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to only allow incoming communications from authorized sources to be routed to authorized destinations.

The configuration would look similar to the example below:

interface GigabitEthernet 0/0/1
description  NIPRNet link
ip address x.x.x.x 255.255.255.0
ip access-group Authorized_Sources_ACL in
...

ip access-list extended Authorized_Sources_ACL
deny ip 1.1.1.0 0.0.0.255 any log
...'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74227r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74141'
  tag rid: 'SV-88815r2_rule'
  tag stig_id: 'CISR-RT-000025'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-80683r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
