control 'SV-25964' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Determine if any system library file has an extended ACL.  If so, this is a finding.'
  desc 'fix', 'Remove the extended ACL(s) from the system library file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29105r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22317'
  tag rid: 'SV-25964r1_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'GEN001310'
  tag fix_id: 'F-26108r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
