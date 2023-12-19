control 'SV-37502' do
  title 'The SMTP service log file must have mode 0644 or less permissive.'
  desc 'If the SMTP service log file is more permissive than 0644, unauthorized users may be allowed to change the log file.'
  desc 'check', %q(Check the mode of the SMTP service log file.

Procedure:
The check procedure is the same for both sendmail and Postfix.
Identify any log files configured for the "mail" service (excluding mail.none) at any severity level and check the permissions. Depending on what system is used for log processing, either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.
For syslog:
# egrep "mail\.[^n][^/]*" /etc/syslog.conf|sed 's/^[^/]*//'|xargs ls -lL

For rsyslog:
# egrep "mail\.[^n][^/]*" /etc/rsyslog.conf|sed 's/^[^/]*//'|xargs ls -lL

If the log file permissions are greater than 0644, this is a finding.)
  desc 'fix', 'Change the mode of the SMTP service log file.

Procedure:
The fix procedure is the same for both sendmail and Postfix.
# chmod 0644 <sendmail log file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36159r4_chk'
  tag severity: 'medium'
  tag gid: 'V-838'
  tag rid: 'SV-37502r3_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'GEN004500'
  tag fix_id: 'F-31410r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
