control 'SV-45615' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', 'By default, rsyslog includes configuration files found in the /etc/rsyslog.d directory.  Check for the include directive” $IncludeConfig /etc/rsyslog.d/*.conf” in /etc/rsyslog.conf and then for the cron log configuration file.
# grep rsyslog.d /etc/rsyslog.conf
# grep cron /etc/rsyslog.d/*.conf

OR

# grep cron /etc/rsyslog.conf
If cron logging is not configured, this is a finding.

Check the configured cron log file found in the cron entry of /etc/syslog (normally /var/log/cron).
# ls -lL /var/log/cron

If this file does not exist, or is older than the last cron job, this is a finding.'
  desc 'fix', 'Edit or create /etc/rsyslog.d/cron.conf and setup cron logging.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-982'
  tag rid: 'SV-45615r1_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'GEN003160'
  tag fix_id: 'F-39014r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
