control 'SV-227844' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', 'Check the syslog configuration file for mail.crit logging configuration.

Procedure:
# more /etc/syslog.conf

Verify a line similar to one of the following lines is present in syslog.conf is configured so that critical mail log data is logged. (Critical log data may also be captured by a remote log host in accordance with GEN005460.)

mail.crit /var/adm/messages
*.crit /var/log/messages

Less severe syslog levels (err, warning, info, and debug) may be substituted for crit, since they will also capture crit level syslog messages.  If syslog is not configured to log critical Sendmail messages, this is a finding.'
  desc 'fix', 'Edit the syslog.conf file and add a configuration line specifying an appropriate destination for mail.crit syslogs.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30006r489907_chk'
  tag severity: 'medium'
  tag gid: 'V-227844'
  tag rid: 'SV-227844r603266_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-29994r489908_fix'
  tag 'documentable'
  tag legacy: ['V-836', 'SV-41546']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
