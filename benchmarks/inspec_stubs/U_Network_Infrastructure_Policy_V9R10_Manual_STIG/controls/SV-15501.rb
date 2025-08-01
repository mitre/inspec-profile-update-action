control 'SV-15501' do
  title 'VPN gateways used to create IP tunnels to transport classified traffic across an unclassified IP network must comply with appropriate physical security protection standards for processing classified information.'
  desc 'When transporting classified data over an unclassified IP network, it is imperative that the network elements deployed to provision the encrypted tunnels are located in a facility authorized to process the data at the proper classification level.'
  desc 'check', 'Review the network topology diagram. If there is a connection between the classified network and the unclassified network for the purpose of tunneling classified traffic across the unclassified IP network, verify that the IPsec VPN gateway used to provision the tunnel is compliant with appropriate physical security protection standards for processing classified information.

If appropriate physical security protection has not been enforced, this is a finding.'
  desc 'fix', 'Employ the necessary physical security protection for the VPN gateway devices used for tunneling classified traffic across the unclassified IP network.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-12967r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14745'
  tag rid: 'SV-15501r2_rule'
  tag stig_id: 'NET1832'
  tag gtitle: 'Demarcation point is not authorized for SIPRNet'
  tag fix_id: 'F-14211r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
