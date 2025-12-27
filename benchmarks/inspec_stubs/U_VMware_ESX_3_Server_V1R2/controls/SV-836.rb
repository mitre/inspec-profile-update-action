control 'SV-836' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', 'Check the syslog configuration file for mail.crit logging configuration.

Procedure:
# more /etc/syslog.conf

Verify a line similar to one of the following lines is present in syslog.conf is configured so that critical mail log data is logged.  (Critical log data may also be captured by a remote log host in accordance with GEN005460.)

mail.crit                             /var/adm/messages
*.crit                                  /var/log/messages

If syslog is not configured to log critical Sendmail messages, this is a finding.'
  desc 'fix', 'Edit the syslog.conf file and add a configuration line specifying an appropriate destination for mail.crit syslogs.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-617r2_chk'
  tag severity: 'medium'
  tag gid: 'V-836'
  tag rid: 'SV-836r2_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'GEN004460'
  tag fix_id: 'F-990r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
