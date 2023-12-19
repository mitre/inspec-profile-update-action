control 'SV-44999' do
  title 'The /etc/group file must not have an extended ACL.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', "Verify /etc/group has no extended ACL.
# ls -l /etc/group
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/group'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42404r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22338'
  tag rid: 'SV-44999r1_rule'
  tag stig_id: 'GEN001394'
  tag gtitle: 'GEN001394'
  tag fix_id: 'F-38414r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
