control 'SV-978' do
  title 'Crontab files must have mode 0600 or less permissive, and files in cron script directories must have mode 0700 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the modes of the crontab and cron job script files.  If the mode is more permissive than 0600 for crontab files or 0700 for cron job script files, this is a finding.'
  desc 'fix', 'Change the modes of crontab files to 0600 and cron job script files to 0700.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-790r2_chk'
  tag severity: 'medium'
  tag gid: 'V-978'
  tag rid: 'SV-978r2_rule'
  tag stig_id: 'GEN003080'
  tag gtitle: 'GEN003080'
  tag fix_id: 'F-1132r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
