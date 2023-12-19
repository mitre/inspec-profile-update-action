control 'SV-38689' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'Determine if any system library file has an extended ACL. If so, this is a finding.

Check to see if extended permissions are disabled. If extended permissions are not disabled, this is a finding.

#aclget < directory >/< file >'
  desc 'fix', 'Remove the extended ACL(s) from the system library file(s) and disable extended permissions.

#acledit < directory >/< file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36962r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22317'
  tag rid: 'SV-38689r1_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'GEN001310'
  tag fix_id: 'F-32228r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
