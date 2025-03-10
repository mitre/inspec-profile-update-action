control 'SV-38282' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions possibly compromising the system.'
  desc 'check', %q(Verify that all manual page files do not have extended ACLs.
# find `env | grep MANPATH | cut -f 2,2 -d "=" | tr ':' ' ' ` -type f  -exec ls -al '{}' | grep '^[a-zA-Z\-]\{10\}+'

If the permissions include a "+" the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the optional ACL from the file(s).
# chacl -z /usr/share/man/* /usr/share/info/* /usr/share/infopage/*'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36315r5_chk'
  tag severity: 'low'
  tag gid: 'V-22316'
  tag rid: 'SV-38282r2_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'GEN001290'
  tag fix_id: 'F-31570r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
