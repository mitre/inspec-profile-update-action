control 'SV-44903' do
  title 'The root accounts home directory must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the unix permissions of the files.'
  desc 'check', %q(Check the root account's home directory has no extended ACL.

# grep "^root" /etc/passwd | awk -F":" ‘{print $6}’

# ls -ld <root home directory>

If the permissions include a '+' the directory has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', "Remove the extended ACL from the root account's home directory.
# setfacl --remove-all <root home directory>"
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22309'
  tag rid: 'SV-44903r1_rule'
  tag stig_id: 'GEN000930'
  tag gtitle: 'GEN000930'
  tag fix_id: 'F-38335r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
