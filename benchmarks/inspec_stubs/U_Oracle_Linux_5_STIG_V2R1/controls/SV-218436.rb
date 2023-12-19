control 'SV-218436' do
  title 'Crontab files must have mode 0600 or less permissive, and files in cron script directories must have mode 0700 or less permissive.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', 'Check the mode of the crontab files.
# ls -lL /var/spool/cron/
# ls -lL /etc/cron.d/
# ls -lL /etc/crontab

If any crontab file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the crontab files.

# chmod 0600 /var/spool/cron/* /etc/cron.d/* /etc/crontab'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19911r562468_chk'
  tag severity: 'medium'
  tag gid: 'V-218436'
  tag rid: 'SV-218436r603259_rule'
  tag stig_id: 'GEN003080'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19909r562469_fix'
  tag 'documentable'
  tag legacy: ['V-978', 'SV-64391']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
