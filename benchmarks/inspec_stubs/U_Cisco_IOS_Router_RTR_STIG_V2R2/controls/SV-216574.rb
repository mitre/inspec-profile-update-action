control 'SV-216574' do
  title 'The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an access control list (ACL), which is a firewall function, or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if the router allows only incoming communications from authorized sources to be routed to authorized destinations. The hypothetical example below allows inbound NTP from server x.1.12.9 only to host x.12.1.21.

ip access-list extended FILTER_PERIMETER
 permit tcp any any established
 …
 …
 …
 permit udp host x.12.1.9 host x.12.1.21 eq ntp
 deny   ip any any log-input

If the router does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to allow only incoming communications from authorized sources to be routed to authorized destinations. 

R1(config)#ip access-list extended FILTER_PERIMETER
R1(config-ext-nacl)#nn permit udp host x.12.1.9 host x.12.1.21 eq ntp
R1(config-ext-nacl)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17809r287106_chk'
  tag severity: 'medium'
  tag gid: 'V-216574'
  tag rid: 'SV-216574r856187_rule'
  tag stig_id: 'CISC-RT-000260'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-17805r287107_fix'
  tag 'documentable'
  tag legacy: ['SV-105687', 'V-96549']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
