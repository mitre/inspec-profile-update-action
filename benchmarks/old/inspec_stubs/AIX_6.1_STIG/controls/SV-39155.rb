control 'SV-39155' do
  title 'The system syslog service must log informational and more severe SMTP service messages.'
  desc 'If informational and more severe SMTP service messages are not logged, malicious activity on the system may go unnoticed.'
  desc 'check', 'Check the syslog configuration file for mail.crit logging configuration. The syslog.conf file critical mail logging option line will typically appear as one of the following examples: 

mail.crit /var/log/syslog 
*.crit /var/log/syslog 
mail.* /var/log/syslog

Procedure: 
# more /etc/syslog.conf 

If syslog is not configured to log critical Sendmail messages, this is a finding.'
  desc 'fix', 'Edit the syslog.conf file and add a configuration line specifying an appropriate destination for mail.crit syslogs.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-836'
  tag rid: 'SV-39155r1_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'GEN004460'
  tag fix_id: 'F-33411r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
