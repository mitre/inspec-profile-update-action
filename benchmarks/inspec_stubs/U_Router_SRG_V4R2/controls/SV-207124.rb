control 'SV-207124' do
  title 'The router must be configured to use encryption for routing protocol authentication.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration.

For every protocol that affects the routing or forwarding tables (where information is exchanged between neighbors), verify that neighbor router authentication is encrypting the authentication key.

If authentication is not encrypting the authentication key, this is a finding.'
  desc 'fix', 'Configure routing protocol authentication to encrypt the authentication key.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7385r382265_chk'
  tag severity: 'medium'
  tag gid: 'V-207124'
  tag rid: 'SV-207124r604135_rule'
  tag stig_id: 'SRG-NET-000168-RTR-000077'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-7385r382266_fix'
  tag 'documentable'
  tag legacy: ['V-55765', 'SV-70019']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
