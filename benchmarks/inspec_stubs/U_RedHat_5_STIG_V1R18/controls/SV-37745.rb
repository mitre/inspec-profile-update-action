control 'SV-37745' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29289'
  tag rid: 'SV-37745r1_rule'
  tag stig_id: 'GEN003080-2'
  tag gtitle: 'GEN003080-2'
  tag fix_id: 'F-32208r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
