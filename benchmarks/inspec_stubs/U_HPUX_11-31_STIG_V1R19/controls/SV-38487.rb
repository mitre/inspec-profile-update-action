control 'SV-38487' do
  title 'The Network Information System (NIS) protocol must not be used.'
  desc 'Due to numerous security vulnerabilities existing within NIS, it must not be used. Possible alternative directory services are NIS+ and LDAP.'
  desc 'check', 'Perform the following to determine if NIS is active on the system.

# ps -ef | grep -v grep | egrep "ypbind|ypserv"

If NIS is found active on the system, this is a finding.'
  desc 'fix', 'Disable the use of NIS. Possible replacements are NIS+ and LDAP-UX.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36720r1_chk'
  tag severity: 'medium'
  tag gid: 'V-867'
  tag rid: 'SV-38487r1_rule'
  tag stig_id: 'GEN006400'
  tag gtitle: 'GEN006400'
  tag fix_id: 'F-32102r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001435']
  tag nist: ['AC-17 (8)']
end
