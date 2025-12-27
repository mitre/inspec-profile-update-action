control 'SV-45639' do
  title 'The at.allow file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Unauthorized modification of the at.allow file could result in Denial of Service to authorized "at" users and the granting of the ability to run "at" jobs to unauthorized users.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/at.allow
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/at.allow'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22390'
  tag rid: 'SV-45639r1_rule'
  tag stig_id: 'GEN003245'
  tag gtitle: 'GEN003245'
  tag fix_id: 'F-39037r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
