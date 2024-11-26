control 'SV-220148' do
  title 'The perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3255.'
  desc 'The routing header can be used maliciously to send a packet through a path where less robust security is in place, rather than through the presumably preferred path of routing protocols. Use of the routing extension header has few legitimate uses other than as implemented by Mobile IPv6. 

The Type 0 Routing Header (RFC 5095) is dangerous because it allows attackers to spoof source addresses and obtain traffic in response, rather than the real owner of the address. Secondly, a packet with an allowed destination address could be sent through a Firewall using the Routing Header functionality, only to bounce to a different node once inside. The Type 1 Routing Header is defined by a specification called "Nimrod Routing", a discontinued project funded by DARPA. Assuming that most implementations will not recognize the Type 1 Routing Header, it must be dropped. The Type 3–255 Routing Header values in the routing type field are currently undefined and should be dropped inbound and outbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3–255.

If the router is not configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3–255, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets with Routing Header of type 0, 1, or 3–255.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-21863r457773_chk'
  tag severity: 'medium'
  tag gid: 'V-220148'
  tag rid: 'SV-220148r604135_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000201'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-21856r457774_fix'
  tag 'documentable'
  tag legacy: ['V-101091', 'SV-110195']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
