control 'SV-38546' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab directory.
# ls -lLd /var/spool/cron/crontabs

If the mode of the crontab directory is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of crontab directories to 0755.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36452r1_chk'
  tag severity: 'medium'
  tag gid: 'V-979'
  tag rid: 'SV-38546r1_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'GEN003100'
  tag fix_id: 'F-1133r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
