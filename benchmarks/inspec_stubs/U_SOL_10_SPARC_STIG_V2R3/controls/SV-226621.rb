control 'SV-226621' do
  title 'Crontab files must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on crontab files may provide unauthorized access to the files.'
  desc 'check', 'Check the permissions of the crontab files.
# ls -lL /var/spool/cron/crontabs/

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [crontab file]'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28782r483275_chk'
  tag severity: 'medium'
  tag gid: 'V-226621'
  tag rid: 'SV-226621r603265_rule'
  tag stig_id: 'GEN003090'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28770r483276_fix'
  tag 'documentable'
  tag legacy: ['SV-26534', 'V-22386']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
