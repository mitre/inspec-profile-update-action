control 'SV-226622' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab directory.
# ls -ld /var/spool/cron/crontabs
If the mode of the crontab directory is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the crontab directory.
# chmod 0755 /var/spool/cron/crontabs'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28783r483278_chk'
  tag severity: 'medium'
  tag gid: 'V-226622'
  tag rid: 'SV-226622r603265_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28771r483279_fix'
  tag 'documentable'
  tag legacy: ['SV-27342', 'V-979']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
