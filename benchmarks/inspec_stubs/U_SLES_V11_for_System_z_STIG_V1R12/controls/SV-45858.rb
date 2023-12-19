control 'SV-45858' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', 'Check the syslog configuration file for mail.crit logging configuration.

Procedure:
# grep "mail\\." /etc/rsyslog.conf 

If syslog is not configured to log critical sendmail messages ("mail.crit" or "mail.*"), this is a finding.'
  desc 'fix', 'Edit the syslog configuration file and add a configuration line specifying an appropriate destination for "mail.crit" syslogs.

For example:
mail.*             -/var/log/mail;RSYSLOG_TraditionalFileFormat'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43154r1_chk'
  tag severity: 'medium'
  tag gid: 'V-836'
  tag rid: 'SV-45858r1_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'GEN004460'
  tag fix_id: 'F-39240r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
