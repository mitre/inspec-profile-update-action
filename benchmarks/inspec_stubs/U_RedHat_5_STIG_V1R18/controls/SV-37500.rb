control 'SV-37500' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', 'Check the syslog configuration file for mail.crit logging configuration. Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Procedure:
# grep "mail\\." /etc/syslog.conf 
Or:
#grep "mail\\." /etc/syslog.conf

If syslog is not configured to log critical sendmail messages ("mail.crit" or "mail.*"), this is a finding.'
  desc 'fix', 'Edit the syslog.conf or rsyslog.conf file and add a configuration line specifying an appropriate destination for "mail.crit" or "mail.*" syslog messages.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36156r2_chk'
  tag severity: 'medium'
  tag gid: 'V-836'
  tag rid: 'SV-37500r3_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'GEN004460'
  tag fix_id: 'F-31407r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
