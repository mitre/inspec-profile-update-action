control 'SV-27357' do
  title 'The cronlog file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the mode of the cron log file.

Procedure:
Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.
Check the configured cron log file found in the cron entry in /etc/syslog.conf or /etc/rsyslog.conf (normally /var/log/cron).
# grep cron /etc/syslog.conf 
Or:
 # grep cron /etc/rsyslog.conf

# ls -lL /var/log/cron

If the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron log file.
# chmod 0600 /var/log/cron'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-28501r2_chk'
  tag severity: 'medium'
  tag gid: 'V-983'
  tag rid: 'SV-27357r2_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'GEN003180'
  tag fix_id: 'F-24602r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
