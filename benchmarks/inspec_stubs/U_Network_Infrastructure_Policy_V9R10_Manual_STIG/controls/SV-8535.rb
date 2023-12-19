control 'SV-8535' do
  title 'The connection between the Channel Service Unit/Data Service Unit (CSU/DSU) and the Local Exchange Carriers (LEC) data service jack (i.e., demarc) as well as any service provider premise equipment must be located in a secure environment.'
  desc 'DOD leased lines carry an aggregate of sensitive and non-sensitive data; therefore unauthorized access must be restricted. Inadequate cable protection can lead to damage and denial of service attacks against the site and the LAN infrastructure.'
  desc 'check', 'Review the network topology to determine external connections and inspect location where CSU/DSUs and data service jacks reside.

If these components are not in a secured environment, this is a finding.'
  desc 'fix', 'Move all critical communications to controlled access areas. Controlled access areas in this case means controlled restriction to authorize site personnel, i.e., dedicated communications rooms or locked cabinets. This is an area afforded entry control at a security level commensurate with the operational requirement. This protection will be sufficient to protect the network from unauthorized personnel. The keys to the locked cabinets and dedicated communications rooms will be controlled and only provided to authorized network/network security individuals.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7430r3_chk'
  tag severity: 'low'
  tag gid: 'V-8049'
  tag rid: 'SV-8535r3_rule'
  tag stig_id: 'NET0140'
  tag gtitle: 'Circuit location is not secure.'
  tag fix_id: 'F-7624r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001121']
  tag nist: ['SC-7 (14)']
end
