control 'SV-980' do
  title 'Cron and crontab directories must be owned by root or bin.'
  desc "Incorrect ownership of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users.  Failure to give ownership of cron or crontab directories to root or to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the owner of the cron and crontab directories.  If any cron or crontab directory is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the owner of the cron and crontab directories to root or bin.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8073r2_chk'
  tag severity: 'medium'
  tag gid: 'V-980'
  tag rid: 'SV-980r2_rule'
  tag stig_id: 'GEN003120'
  tag gtitle: 'GEN003120'
  tag fix_id: 'F-1134r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
