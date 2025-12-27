control 'SV-45599' do
  title 'Files in cron script directories must have mode 0700 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of scripts in cron job directories.

ls -lL /etc/cron.{d,daily,hourly,monthly,weekly}
If any cron script has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the cron scripts.
# chmod
 go-rwx /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/*
/etc/cron.monthly/* /etc/cron.weekly/*'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42960r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29289'
  tag rid: 'SV-45599r2_rule'
  tag stig_id: 'GEN003080-2'
  tag gtitle: 'GEN003080-2'
  tag fix_id: 'F-38997r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
