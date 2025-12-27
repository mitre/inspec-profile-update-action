control 'SV-80619' do
  title 'The HP FlexFabric Switch must only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an ACL (which is a firewall function) or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering, but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

Traffic can be restricted directly by an ACL (which is a firewall function), or by Policy Routing. This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'Review the HP FlexFabric Switch configuration to determine if the switch only allows incoming communications from authorized sources to be routed to authorized destinations. This requirement can be met by applying an ingress filter to an external-facing interface as shown in the following example:
acl number 3001
 rule 1 deny ip source 192.168.3.121 0
 rule 2  permit ip source 192.100.1.0 0.0.0.255 destination 192.200.2.0 0.0.0.255

interface Ten-GigabitEthernet1/0/21
ip address 102.17.17.2 255.255.255.252
packet-filter 3001 inbound

If the HP FlexFabric Switch allows incoming communications from unauthorized sources or to unauthorized destinations, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to only allow incoming communications from authorized sources to be routed to authorized destinations.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66129'
  tag rid: 'SV-80619r1_rule'
  tag stig_id: 'HFFS-RT-000021'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-72205r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
