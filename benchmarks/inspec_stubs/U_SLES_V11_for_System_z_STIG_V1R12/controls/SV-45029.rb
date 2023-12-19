control 'SV-45029' do
  title 'User home directories must not have extended ACLs.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', "Verify user home directories have no extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld 
If the permissions include a '+', the file has an extended ACL this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [user home directory with extended ACL]'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42415r1_chk'
  tag severity: 'low'
  tag gid: 'V-22350'
  tag rid: 'SV-45029r1_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'GEN001490'
  tag fix_id: 'F-38443r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
