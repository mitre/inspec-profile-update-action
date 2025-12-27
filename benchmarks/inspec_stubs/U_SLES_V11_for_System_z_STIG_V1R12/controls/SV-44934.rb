control 'SV-44934' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', "Check that network services daemon files have no extended ACLs.
# ls -la /usr/sbin
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/sbin/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42368r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22313'
  tag rid: 'SV-44934r1_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'GEN001190'
  tag fix_id: 'F-38359r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
