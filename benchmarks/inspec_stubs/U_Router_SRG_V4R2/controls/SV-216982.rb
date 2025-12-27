control 'SV-216982' do
  title 'The router must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information. This includes BGP, RIP, OSPF, EIGRP, IS-IS and LDP.)
  desc 'check', 'Review the router configuration.

For every protocol that affects the routing or forwarding tables (where information is exchanged between neighbors), verify that neighbor router authentication is enabled.

If authentication is not enabled, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-18212r382652_chk'
  tag severity: 'medium'
  tag gid: 'V-216982'
  tag rid: 'SV-216982r604135_rule'
  tag stig_id: 'SRG-NET-000230-RTR-000001'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-18210r382653_fix'
  tag 'documentable'
  tag legacy: ['V-55757', 'SV-70011']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
