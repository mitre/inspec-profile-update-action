control 'SV-239963' do
  title 'The Cisco ASA VPN gateway must be configured to renegotiate the IPsec Security Association after eight hours or less.'
  desc 'The IPsec SA and its corresponding key will expire either after the number of seconds or amount of traffic volume has exceeded the configured limit. A new SA is negotiated before the lifetime threshold of the existing SA is reached to ensure that a new SA is ready for use when the old one expires. The longer the lifetime of the IPsec SA, the longer the lifetime of the session key used to protect IP traffic. The SA is less secure with a longer lifetime because an attacker has a greater opportunity to collect traffic encrypted by the same key and subject it to cryptanalysis. However, a shorter lifetime causes IPsec peers to renegotiate Phase 2, more often resulting in the expenditure of additional resources.

Specify the lifetime (in seconds) of an Internet Key Exchange (IKE) security association (SA). When the SA expires, it is replaced by a new SA, the Security Parameter Index (SPI), or terminated if the peer cannot be contacted for renegotiation.'
  desc 'check', 'Verify the VPN gateway renegotiates the security association after eight hours or less as shown in the example below.

crypto map IPSEC_MAP 10 match address SITE1_SITE2
crypto map IPSEC_MAP 10 set peer x.x.x.x 
…
…
…
crypto map IPSEC_MAP 10 set security-association lifetime seconds 3600

If the VPN Gateway does not renegotiate the security association after eight hours or less, this is a finding.'
  desc 'fix', 'Configure the VPN gateway to renegotiate the security association after eight hours or less as shown in the example below.

ASA1(config)# crypto map IPSEC_MAP 10 set security-association lifetime seconds 28800
ASA1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43196r666293_chk'
  tag severity: 'medium'
  tag gid: 'V-239963'
  tag rid: 'SV-239963r856172_rule'
  tag stig_id: 'CASA-VN-000350'
  tag gtitle: 'SRG-NET-000337-VPN-001290'
  tag fix_id: 'F-43155r666294_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
