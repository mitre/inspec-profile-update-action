control 'SV-8540' do
  title 'All network infrastructure devices must be located in a secure room with limited access.'
  desc 'If all communications devices are not installed within controlled access areas, risk of unauthorized access and equipment failure exists, which could result in denial of service or security compromise.  It is not sufficient to limit access to only the outside world or non-site personnel.  Not everyone within the site has the need-to-know or the need-for-access to communication devices.'
  desc 'check', 'Inspect the site to validate physical network components are in a secure environment with limited access. 

If there are any network components not located in a secure environment, this is a finding.'
  desc 'fix', 'Move all critical communications into controlled access areas. Controlled access area in this case means controlled restriction to authorize site personnel, i.e., dedicated communications rooms or locked cabinets. This is an area afforded entry control at a security level commensurate with the operational requirement. This protection will be sufficient to protect the network from unauthorized personnel. The keys to the locked cabinets and dedicated communications rooms will be controlled and only provided to authorized network/network security individuals.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7435r5_chk'
  tag severity: 'medium'
  tag gid: 'V-8054'
  tag rid: 'SV-8540r3_rule'
  tag stig_id: 'NET0210'
  tag gtitle: 'Network devices are not stored in secure Comm room'
  tag fix_id: 'F-7629r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000921']
  tag nist: ['PE-3 a 2']
end
