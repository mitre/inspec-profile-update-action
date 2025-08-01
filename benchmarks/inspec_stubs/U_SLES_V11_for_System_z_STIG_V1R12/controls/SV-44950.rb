control 'SV-44950' do
  title 'All manual page files must not have extended ACLs.'
  desc 'If manual pages are compromised, misleading information could be inserted, causing actions to compromise the system.'
  desc 'check', "Verify all manual page files have no extended ACLs.
# ls -lL /usr/share/man /usr/share/man/man* /usr/share/info 
If the permissions include a '+', the file has an extended ACL this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/share/man/* /usr/share/man/man* /usr/share/info/*'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42376r1_chk'
  tag severity: 'low'
  tag gid: 'V-22316'
  tag rid: 'SV-44950r1_rule'
  tag stig_id: 'GEN001290'
  tag gtitle: 'GEN001290'
  tag fix_id: 'F-38374r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
