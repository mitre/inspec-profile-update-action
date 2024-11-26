control 'SV-227949' do
  title 'The Network Information System (NIS) protocol must not be used.'
  desc 'Due to numerous security vulnerabilities existing within NIS, it must not be used.  Possible alternative directory services are NIS+ and LDAP.'
  desc 'check', "Perform the following to determine if NIS is active on the system.

# ps -ef | egrep '(ypbind|ypserv)'

If NIS is found active on the system, this is a finding."
  desc 'fix', 'Disable the use of NIS.  Possible replacements are NIS+ and LDAP.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30111r490267_chk'
  tag severity: 'medium'
  tag gid: 'V-227949'
  tag rid: 'SV-227949r603266_rule'
  tag stig_id: 'GEN006400'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-30099r490268_fix'
  tag 'documentable'
  tag legacy: ['V-867', 'SV-867']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
