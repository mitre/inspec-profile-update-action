control 'SV-45628' do
  title 'The cron.deny file must not have an extended ACL.'
  desc 'If there are excessive file permissions for the cron.deny file, sensitive information could be viewed or edited by unauthorized users.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/cron.deny
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42994r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22389'
  tag rid: 'SV-45628r1_rule'
  tag stig_id: 'GEN003210'
  tag gtitle: 'GEN003210'
  tag fix_id: 'F-39026r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
