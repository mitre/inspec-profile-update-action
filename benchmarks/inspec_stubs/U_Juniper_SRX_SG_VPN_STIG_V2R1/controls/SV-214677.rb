control 'SV-214677' do
  title 'The Juniper SRX Services Gateway VPN must use Internet Key Exchange (IKE) for IPsec VPN Security Associations (SAs).'
  desc 'Without IKE, the SPI is manually specified for each security association. IKE peers will negotiate the encryption algorithm and authentication or hashing methods as well as generate the encryption keys. 

An IPsec SA is established using either Internet Key Exchange (IKE) or manual configuration. When using IKE, the security associations are established when needed and expire after a period of time or volume of traffic threshold. If manually configured, they are established as soon as the configuration is complete at both end points and they do not expire. When using IKE, the Security Parameter Index (SPI) for each security association is a pseudo-randomly derived number. 

With manual configuration of the IPsec security association, both the cipher key and authentication key are static. Hence, if the keys are compromised, the traffic being protected by the current IPsec tunnel can be decrypted as well as traffic in any future tunnels established by this SA. Furthermore, the peers are not authenticated prior to establishing the SA, which could result in a rogue device establishing an IPsec SA with either of the VPN end points.

IKE provides primary authentication to verify the identity of the remote system before negotiation begins. This feature is lost when the IPsec security associations are manually configured, which results in a non-terminating session using static pre-shared keys.'
  desc 'check', 'Verify the IKE protocol is specified for all IPsec VPNs.

[edit]
show security ipsec vpn 

If the IKE protocol is not specified as an option on all VPN gateways, this is a finding.'
  desc 'fix', 'The following example commands configure an IPsec VPN to use the IKE gateway information.

[edit]
set security ipsec vpn <VPN-GWY-NAME> ike gateway <IKE-PEER-NAME>'
  impact 0.7
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15878r297618_chk'
  tag severity: 'high'
  tag gid: 'V-214677'
  tag rid: 'SV-214677r385561_rule'
  tag stig_id: 'JUSX-VN-000010'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-15876r297619_fix'
  tag 'documentable'
  tag legacy: ['V-66619', 'SV-81109']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
