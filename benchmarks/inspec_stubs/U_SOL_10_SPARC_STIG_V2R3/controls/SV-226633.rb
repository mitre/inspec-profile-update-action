control 'SV-226633' do
  title 'The at.allow file must not have an extended ACL.'
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  Unauthorized modification of the at.allow file could result in Denial of Service to authorized at users and the granting of the ability to run at jobs to unauthorized users.'
  desc 'check', 'Check the permissions of the file.
# ls -lL /etc/cron.d/at.allow
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/cron.d/at.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28794r483311_chk'
  tag severity: 'medium'
  tag gid: 'V-226633'
  tag rid: 'SV-226633r603265_rule'
  tag stig_id: 'GEN003245'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28782r483312_fix'
  tag 'documentable'
  tag legacy: ['SV-26550', 'V-22390']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
