control 'SV-981' do
  title 'Cron and crontab directories must be group-owned by root, sys, bin or cron.'
  desc "To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.  Failure to give group-ownership of cron or crontab directories to a system group provides the designated group and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group owner of cron and crontab directories.  If a cron or crontab directory is not group-owned by root, sys, bin, or cron, this is a finding.'
  desc 'fix', 'Change the group owner of the cron and crontab directories to root, sys, bin, or cron.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8074r2_chk'
  tag severity: 'medium'
  tag gid: 'V-981'
  tag rid: 'SV-981r2_rule'
  tag stig_id: 'GEN003140'
  tag gtitle: 'GEN003140'
  tag fix_id: 'F-1135r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
