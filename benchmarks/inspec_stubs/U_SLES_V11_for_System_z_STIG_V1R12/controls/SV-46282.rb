control 'SV-46282' do
  title 'The Network Information System (NIS) protocol must not be used.'
  desc 'Due to numerous security vulnerabilities existing within NIS, it must not be used.  Possible alternative directory services are NIS+ and LDAP.'
  desc 'check', 'Perform the following to determine if NIS is active on the system:

# ps -ef | grep ypbind

If NIS is found active on the system, this is a finding.'
  desc 'fix', 'Disable the use of NIS. Use as a replacement NIS+ or LDAP.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-36937r2_chk'
  tag severity: 'medium'
  tag gid: 'V-867'
  tag rid: 'SV-46282r1_rule'
  tag stig_id: 'GEN006400'
  tag gtitle: 'GEN006400'
  tag fix_id: 'F-39579r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
