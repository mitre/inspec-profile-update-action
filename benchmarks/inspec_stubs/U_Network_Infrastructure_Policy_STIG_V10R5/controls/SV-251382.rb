control 'SV-251382' do
  title 'VPN gateways used to create IP tunnels to transport classified traffic across an unclassified IP network must comply with appropriate physical security protection standards for processing classified information.'
  desc 'When transporting classified data over an unclassified IP network, it is imperative that the network elements deployed to provision the encrypted tunnels are located in a facility authorized to process the data at the proper classification level.'
  desc 'check', 'Review the network topology diagram. If there is a connection between the classified network and the unclassified network for the purpose of tunneling classified traffic across the unclassified IP network, verify that the IPsec VPN gateway used to provision the tunnel is compliant with appropriate physical security protection standards for processing classified information.

If appropriate physical security protection has not been enforced, this is a finding.'
  desc 'fix', 'Employ the necessary physical security protection for the VPN gateway devices used for tunneling classified traffic across the unclassified IP network.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54817r806099_chk'
  tag severity: 'medium'
  tag gid: 'V-251382'
  tag rid: 'SV-251382r806101_rule'
  tag stig_id: 'NET1832'
  tag gtitle: 'NET1832'
  tag fix_id: 'F-54770r806100_fix'
  tag 'documentable'
  tag legacy: ['V-14745', 'SV-15501']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
