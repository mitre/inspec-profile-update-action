control 'SV-27352' do
  title 'Cron logging must be implemented.'
  desc 'Cron logging can be used to trace the successful or unsuccessful execution of cron jobs.  It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.'
  desc 'check', 'Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file. 
# grep cron /etc/syslog.conf
Or:
# grep cron /etc/rsyslog.conf
If cron logging is not configured, this is a finding.

Check the configured cron log file found in the cron entry of /etc/syslog.conf or /etc/rsyslog.conf (normally /var/log/cron).
# ls -lL /var/log/cron

If this file does not exist, or is older than the last cron job, this is a finding.'
  desc 'fix', 'Edit /etc/syslog.conf or /etc/rsyslog.conf and setup cron logging'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-28494r2_chk'
  tag severity: 'medium'
  tag gid: 'V-982'
  tag rid: 'SV-27352r2_rule'
  tag stig_id: 'GEN003160'
  tag gtitle: 'GEN003160'
  tag fix_id: 'F-31389r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
