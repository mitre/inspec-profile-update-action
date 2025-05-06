control 'SV-979' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of crontab directories.  If any have a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of crontab directories to 0755.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8072r2_chk'
  tag severity: 'medium'
  tag gid: 'V-979'
  tag rid: 'SV-979r2_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'GEN003100'
  tag fix_id: 'F-1133r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
