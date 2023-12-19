control 'SV-227748' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab directory.
# ls -ld /var/spool/cron/crontabs
If the mode of the crontab directory is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the crontab directory.
# chmod 0755 /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29910r488828_chk'
  tag severity: 'medium'
  tag gid: 'V-227748'
  tag rid: 'SV-227748r603266_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29898r488829_fix'
  tag 'documentable'
  tag legacy: ['V-979', 'SV-27342']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
