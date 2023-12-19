control 'SV-27342' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'fix', 'Change the mode of the crontab directory.
# chmod 0755 /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-979'
  tag rid: 'SV-27342r1_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'GEN003100'
  tag fix_id: 'F-24581r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
