control 'SV-45619' do
  title 'The cronlog file must have mode 0600 or less permissive.'
  desc 'Cron logs contain reports of scheduled system activities and must be protected from unauthorized access or manipulation.'
  desc 'check', 'Check the mode of the cron log file.

Procedure:

Check the configured cron log file found in the cron entry of the rsyslog configuration (normally /var/log/cron).
# grep cron /etc/rsyslog.conf /etc/rsyslog.d/*.conf
# ls -lL /var/log/cron

If the mode is more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the cron log file.
# chmod 0600 /var/log/cron'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-983'
  tag rid: 'SV-45619r1_rule'
  tag stig_id: 'GEN003180'
  tag gtitle: 'GEN003180'
  tag fix_id: 'F-39017r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
