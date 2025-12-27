control 'SV-75391' do
  title 'The Arista Multilayer Switch must not enable the RIP routing protocol.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Review the router configuration to determine if RIP is enabled via the "show running-config" command. RIP is disabled by default on an Arista switch and is only enabled when explicitly configured. If a configuration statement enabling RIP is in the Arista Multilayer Switch configuration, this is a finding.'
  desc 'fix', 'Disable RIP via the "no router rip" command.'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60933'
  tag rid: 'SV-75391r1_rule'
  tag stig_id: 'AMLS-L3-000320'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-66645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
