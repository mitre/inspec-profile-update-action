control 'SV-26036' do
  title 'Crontab files must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on crontab files may provide unauthorized access to the files.'
  desc 'check', 'Check the permissions of the crontab files.
# ls -lL /var/spool/cron/crontabs/

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the crontab file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22386'
  tag rid: 'SV-26036r1_rule'
  tag stig_id: 'GEN003090'
  tag gtitle: 'GEN003090'
  tag fix_id: 'F-26238r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
