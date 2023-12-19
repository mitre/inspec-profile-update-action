control 'SV-207252' do
  title 'The IPsec VPN Gateway must use Internet Key Exchange (IKE) for IPsec VPN Security Associations (SAs).'
  desc 'Without IKE, the SPI is manually specified for each security association. IKE peers will negotiate the encryption algorithm and authentication or hashing methods as well as generate the encryption keys.

An IPsec SA is established using either Internet Key Exchange (IKE) or manual configuration. When using IKE, the security associations are established when needed and expire after a period of time or volume of traffic threshold. If manually configured, they are established as soon as the configuration is complete at both end points and they do not expire. When using IKE, the Security Parameter Index (SPI) for each security association is a pseudo-randomly derived number.

With manual configuration of the IPsec security association, both the cipher key and authentication key are static. Hence, if the keys are compromised, the traffic being protected by the current IPsec tunnel can be decrypted as well as traffic in any future tunnels established by this SA. Furthermore, the peers are not authenticated prior to establishing the SA, which could result in a rogue device establishing an IPsec SA with either of the VPN end points.

IKE provides primary authentication to verify the identity of the remote system before negotiation begins. This feature is lost when the IPsec security associations are manually configured, which results in a non-terminating session using static pre-shared keys.'
  desc 'check', 'Verify the IKE protocol is specified for all IPsec VPNs.

If the IKE protocol is not specified as an option on all VPN gateways, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use IKE and IPsec VPN SAs.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7512r378377_chk'
  tag severity: 'high'
  tag gid: 'V-207252'
  tag rid: 'SV-207252r608988_rule'
  tag stig_id: 'SRG-NET-000512-VPN-002220'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7512r378378_fix'
  tag 'documentable'
  tag legacy: ['V-97199', 'SV-106337']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
