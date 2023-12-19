control 'SV-218439' do
  title 'Cron and crontab directories must have mode 0755 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and to prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab directories.

Procedure:
# ls -ld /var/spool/cron

# ls -ld /etc/cron.d /etc/crontab /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
or 
# ls -ld /etc/cron*|grep -v deny

If the mode of any of the crontab directories is more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the crontab directories.

# chmod 0755 <crontab directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19914r562477_chk'
  tag severity: 'medium'
  tag gid: 'V-218439'
  tag rid: 'SV-218439r603259_rule'
  tag stig_id: 'GEN003100'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19912r562478_fix'
  tag 'documentable'
  tag legacy: ['V-979', 'SV-64375']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
