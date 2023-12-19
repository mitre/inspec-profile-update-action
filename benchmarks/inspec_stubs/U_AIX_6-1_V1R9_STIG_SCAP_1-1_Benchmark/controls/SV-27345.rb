control 'SV-27345' do
  title 'Cron and crontab directories must be owned by root or bin.'
  desc "Incorrect ownership of the cron or crontab directories could permit unauthorized users the ability to alter cron jobs and run automated jobs as privileged users.  Failure to give ownership of cron or crontab directories to root or to bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the owner of the crontab directory.
# chown root /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-980'
  tag rid: 'SV-27345r1_rule'
  tag stig_id: 'GEN003120'
  tag gtitle: 'GEN003120'
  tag fix_id: 'F-24583r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
