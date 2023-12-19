control 'SV-38782' do
  title 'Crontab files must not have extended ACLs.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  ACLs on crontab files may provide unauthorized access to the files.'
  desc 'check', 'Check the permissions of the crontab files.
Get a listing of crontab files.
# ls /var/spool/cron/crontabs

Check all of the crontabs listed for an extended ACL.
# aclget <directory>/<file> 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the crontab file(s) and disable extended permissions.
  
#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37204r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22386'
  tag rid: 'SV-38782r1_rule'
  tag stig_id: 'GEN003090'
  tag gtitle: 'GEN003090'
  tag fix_id: 'F-32474r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
