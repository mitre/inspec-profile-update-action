control 'SV-218437' do
  title 'Files in cron script directories must have mode 0700 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of scripts in cron job directories.
# ls -lL /etc/cron.daily/
# ls -lL /etc/cron.hourly/
# ls -lL /etc/cron.monthly/
# ls -lL /etc/cron.weekly/

If any cron script has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the cron scripts.
# chmod 0700 /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19912r562471_chk'
  tag severity: 'medium'
  tag gid: 'V-218437'
  tag rid: 'SV-218437r603259_rule'
  tag stig_id: 'GEN003080-2'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19910r562472_fix'
  tag 'documentable'
  tag legacy: ['V-29289', 'SV-64385']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
