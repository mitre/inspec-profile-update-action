control 'SV-27340' do
  title 'Crontab files must have mode 0600 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab files.
# ls -lL /var/spool/cron/crontabs/
If any crontab file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the crontab files.
# chmod 0600 /var/spool/cron/crontabs/*'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28476r1_chk'
  tag severity: 'medium'
  tag gid: 'V-978'
  tag rid: 'SV-27340r1_rule'
  tag stig_id: 'GEN003080'
  tag gtitle: 'GEN003080'
  tag fix_id: 'F-24579r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
