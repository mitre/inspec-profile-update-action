control 'SV-218540' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20015r555818_chk'
  tag severity: 'medium'
  tag gid: 'V-218540'
  tag rid: 'SV-218540r603259_rule'
  tag stig_id: 'GEN004460'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-20013r555819_fix'
  tag 'documentable'
  tag legacy: ['V-836', 'SV-63749']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
