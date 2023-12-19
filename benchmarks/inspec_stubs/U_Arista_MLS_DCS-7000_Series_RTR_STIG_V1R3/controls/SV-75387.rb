control 'SV-75387' do
  title 'The Arista Multilayer Switch must only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an ACL (which is a firewall function) or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

Traffic can be restricted directly by an ACL (which is a firewall function), or by Policy Routing. This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'Review the router configuration to determine if the router only allows incoming communications from authorized sources to be routed to authorized destinations.

To verify an ACL is configured to allow only incoming communications from authorized sources, execute a "show ip access-list" command and verify the pertinent permit and deny statements are in place. Validate the access list is configured on the appropriate interface via the "show ip access-list summary" command or by reviewing the interface configuration viewable in the "show running-config" command.

If PBR is being used, verify the appropriate policy maps have been configured by reviewing the switch running-config via the "show running-config" command.

If the router does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'Configure the router to only allow incoming communications from authorized sources to be routed to authorized destinations.

Implement access control lists or policy-based routing as defined in the Arista Configuration Manual, chapters 18 and 22 respectively.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60929'
  tag rid: 'SV-75387r1_rule'
  tag stig_id: 'AMLS-L3-000300'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-66641r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
