control 'SV-37501' do
  title 'The SMTP service log file must be owned by root.'
  desc 'If the SMTP service log file is not owned by root, then unauthorized personnel may modify or delete the file to hide a system compromise.'
  desc 'check', %q(Locate any mail log files by checking the syslog configuration file.

Procedure:
The check procedure is the same for both sendmail and Postfix.
Identify any log files configured for the "mail" service (excluding mail.none) at any severity level and check the ownership. Depending on what system is used for log processing, either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.
For syslog:
# egrep "mail\.[^n][^/]*" /etc/syslog.conf|sed 's/^[^/]*//'|xargs ls -lL

For rsyslog:
# egrep "mail\.[^n][^/]*" /etc/rsyslog.conf|sed 's/^[^/]*//'|xargs ls -lL


If any mail log file is not owned by root, this is a finding.)
  desc 'fix', 'Change the ownership of the sendmail log file.

Procedure:
The fix procedure is the same for both sendmail and Postfix.
# chown root <sendmail log file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36158r4_chk'
  tag severity: 'medium'
  tag gid: 'V-837'
  tag rid: 'SV-37501r3_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'GEN004480'
  tag fix_id: 'F-31408r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
