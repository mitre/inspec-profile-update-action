control 'SV-37238' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions to compromise the system.'
  desc 'check', "Verify all manual page files have no extended ACLs.
# ls -lLR /usr/share/man /usr/share/info /usr/share/infopage

If the permissions include a '+', the file has an extended ACL this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/share/man/* /usr/share/info/* /usr/share/infopage/*'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35929r2_chk'
  tag severity: 'low'
  tag gid: 'V-22316'
  tag rid: 'SV-37238r2_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'GEN001290'
  tag fix_id: 'F-31185r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
