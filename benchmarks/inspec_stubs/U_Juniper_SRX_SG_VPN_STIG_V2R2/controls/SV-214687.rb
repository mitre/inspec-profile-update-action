control 'SV-214687' do
  title 'The Juniper SRX Services Gateway VPN must use FIPS 140-2 compliant mechanisms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity and DoD data may be compromised.

Network elements utilizing encryption are required to use FIPS compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Verify IPsec is defined and configured using FIPS-complaint protocols.

[edit]
show security ipsec vpn

If the IPSEC policy and VP are not configured to use FIPS 140-2 compliant mechanisms for authentication to a cryptographic module, this is a finding.'
  desc 'fix', 'After configuring the Internet Key Exchange (IKE) gateway and IPsec policy, the following commands configure an IPsec policy, enabling Perfect Forward Secrecy (PFS) using Diffie-Hellman group
14 and associating the IPsec proposal configured in the previous example.

set security ipsec policy IPSEC-POLICY perfect-forward-secrecy keys group14
set security ipsec policy IPSEC-POLICY proposals IPSEC-PROPOSAL

The following commands define an IPsec VPN using a secure tunnel interface, specifying the IKE gateway information, IPsec policy, and tunnel establishment policy. Alternatively, administrators can configure on-traffic tunnel establishment.

[edit]
set security ipsec vpn VPN bind-interface st0.0
set security ipsec vpn VPN ike gateway IKE-PEER
set security ipsec vpn VPN ike ipsec-policy IPSEC-POLICY
set security ipsec vpn VPN establish-tunnels immediately'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15888r297648_chk'
  tag severity: 'medium'
  tag gid: 'V-214687'
  tag rid: 'SV-214687r385516_rule'
  tag stig_id: 'JUSX-VN-000020'
  tag gtitle: 'SRG-NET-000168'
  tag fix_id: 'F-15886r297649_fix'
  tag 'documentable'
  tag legacy: ['SV-81157', 'V-66667']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
