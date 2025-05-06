control 'SV-214676' do
  title 'The Juniper SRX Services Gateway VPN must ensure inbound and outbound traffic is configured with a security policy in compliance with information flow control policies.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated, capabilities increase risk and makes remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. 

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets). 

In phase-2, another negotiation is performed, detailing the parameters for the IPsec connection. New keying material using the Diffie-Hellman key exchange established in phase-1 is used to provide session keys used to protecting the VPN data flow. If Perfect-Forwarding-Secrecy (PFS) is used, a new Diffie-Hellman exchange is performed for each phase-2 negotiation. While this is slower, it makes sure that no keys are dependent on any other previously used keys; no keys are extracted from the same initial keying material. This is to make sure that, in the unlikely event that some key was compromised; no subsequent keys can be derived.'
  desc 'check', 'Verify an IPsec policy is configured and used to control the VPN information flow.

[edit]
show security ipsec

Inspect the security policy.

If VPN traffic is not configured and controlled using an IPsec policy, this is a finding.'
  desc 'fix', 'The following example command is an example of an IPsec policy.

[edit]
set security ipsec policy <IPSEC-POLICY> perfect-forward-secrecy keys group14
set security ipsec policy <IPSEC-POLICY> proposals <IPSEC-PROPOSAL>

The following command is an example of how to define an IPsec VPN using the IPsec policy and a secure tunnel interface. Alternatively, administrators can configure on-traffic tunnel establishment.

[edit]
set security ipsec vpn <VPN> bind-interface st0.0
set security ipsec vpn <VPN> ike gateway <IKE-PEER>
set security ipsec vpn <VPN> ike ipsec-policy <IPSEC-POLICY>
set security ipsec vpn <VPN> establish-tunnels immediately

For site-to-site VPN implementation, the SRX device is configured to route traffic over the IPsec VPN’s secure tunnel interface by establishing a route with the next-hop specified as the secure tunnel interface. The following commands configure an IPv4 and IPv6 static route for their respective secure tunnels.

set routing-options static route <IPv4 network/netmask> next-hop st0.0
set routing-options rib inet6.0 static route <IPv6 network/netmask> next-hop st0.1'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15877r297615_chk'
  tag severity: 'medium'
  tag gid: 'V-214676'
  tag rid: 'SV-214676r382735_rule'
  tag stig_id: 'JUSX-VN-000009'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-15875r297616_fix'
  tag 'documentable'
  tag legacy: ['SV-81141', 'V-66651']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
