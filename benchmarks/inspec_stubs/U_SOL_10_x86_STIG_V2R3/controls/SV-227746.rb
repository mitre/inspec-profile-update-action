control 'SV-227746' do
  title 'Crontab files must have mode 0600 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab files.
# ls -lL /var/spool/cron/crontabs/
If any crontab file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the crontab files.
# chmod 0600 /var/spool/cron/crontabs/*'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29908r488822_chk'
  tag severity: 'medium'
  tag gid: 'V-227746'
  tag rid: 'SV-227746r603266_rule'
  tag stig_id: 'GEN003080'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29896r488823_fix'
  tag 'documentable'
  tag legacy: ['V-978', 'SV-27340']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
