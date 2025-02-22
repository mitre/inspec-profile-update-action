control 'SV-218450' do
  title 'The at.allow file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Unauthorized modification of the at.allow file could result in Denial of Service to authorized "at" users and the granting of the ability to run "at" jobs to unauthorized users.'
  desc 'check', "Check the permissions of the file.
# ls -lL /etc/at.allow
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/at.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19925r562507_chk'
  tag severity: 'medium'
  tag gid: 'V-218450'
  tag rid: 'SV-218450r603259_rule'
  tag stig_id: 'GEN003245'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19923r562508_fix'
  tag 'documentable'
  tag legacy: ['V-22390', 'SV-64347']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
