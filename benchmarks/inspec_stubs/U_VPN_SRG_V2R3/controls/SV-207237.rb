control 'SV-207237' do
  title 'The IPsec VPN Gateway must renegotiate the security association after 8 hours or less, or an organization-defined period.'
  desc 'The IPsec SA and its corresponding key will expire either after the number of seconds or amount of traffic volume has exceeded the configured limit. A new SA is negotiated before the lifetime threshold of the existing SA is reached to ensure that a new SA is ready for use when the old one expires. The longer the lifetime of the IPsec SA, the longer the lifetime of the session key used to protect IP traffic. The SA is less secure with a longer lifetime because an attacker has a greater opportunity to collect traffic encrypted by the same key and subject it to cryptanalysis. However, a shorter lifetime causes IPsec peers to renegotiate Phase II more often resulting in the expenditure of additional resources.

Specify the lifetime (in seconds) of an Internet Key Exchange (IKE) security association (SA). When the SA expires, it is replaced by a new SA, the security parameter index (SPI), or terminated if the peer cannot be contacted for renegotiation.'
  desc 'check', 'Verify the IPsec VPN Gateway renegotiates the security association after 8 hours or less, or an organization-defined period.

If the IPsec VPN Gateway does not renegotiate the security association after 8 hours or less, or an organization-defined period, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to renegotiate the security association after 8 hours or less, or an organization-defined period.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7497r378332_chk'
  tag severity: 'medium'
  tag gid: 'V-207237'
  tag rid: 'SV-207237r608988_rule'
  tag stig_id: 'SRG-NET-000337-VPN-001290'
  tag gtitle: 'SRG-NET-000337'
  tag fix_id: 'F-7497r378333_fix'
  tag 'documentable'
  tag legacy: ['SV-106291', 'V-97153']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
