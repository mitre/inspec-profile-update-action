control 'SV-37742' do
  title 'The Network Information System (NIS) protocol must not be used.'
  desc 'Due to numerous security vulnerabilities existing within NIS, it must not be used.  Possible alternative directory services are NIS+ and LDAP.'
  desc 'fix', 'Disable the use of NIS/NIS+. Use as a replacement Kerberos or LDAP.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-867'
  tag rid: 'SV-37742r1_rule'
  tag stig_id: 'GEN006400'
  tag gtitle: 'GEN006400'
  tag fix_id: 'F-32202r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
