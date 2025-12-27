control 'SV-207206' do
  title 'The Remote Access VPN Gateway must be configured to prohibit Point-to-Point Tunneling Protocol (PPTP) and L2F.'
  desc 'The PPTP and L2F are obsolete method for implementing virtual private networks. Both protocols may be easy to use and readily available, but they have many well-known security issues and exploits. Encryption and authentication are both weak.'
  desc 'check', 'Verify the VPN Gateway is configured to prohibit PPTP and L2F.

If the VPN Gateway does not be configured to prohibit PPTP and L2F, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to prohibit PPTP and L2F.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7466r378239_chk'
  tag severity: 'medium'
  tag gid: 'V-207206'
  tag rid: 'SV-207206r608988_rule'
  tag stig_id: 'SRG-NET-000132-VPN-000470'
  tag gtitle: 'SRG-NET-000132'
  tag fix_id: 'F-7466r378240_fix'
  tag 'documentable'
  tag legacy: ['V-97083', 'SV-106221']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
