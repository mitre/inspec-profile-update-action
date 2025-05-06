control 'SV-37503' do
  title 'The SMTP service log file must not have an extended ACL.'
  desc 'If the SMTP service log file has an extended ACL, unauthorized users may be allowed to access or to modify the log file.'
  desc 'check', %q(Depending on what system is used for log processing, either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file. Examine /etc/syslog.conf or /etc/rsyslog.conf and determine the log file(s) receiving logs for "mail.crit", "mail.debug", mail.*, or "*.crit".

Procedure:
This check is applicable to both Postfix and sendmail servers.
Check the permissions on these log files.Identify any log files configured for "*.crit" and the "mail" service (excluding mail.none) and at any severity level.
For syslog:
# egrep "(\*.crit|mail\.[^n][^/]*)" /etc/syslog.conf|sed 's/^[^/]*//'|xargs ls -lL

For rsyslog:
# egrep "(\*.crit|mail\.[^n][^/]*)" /etc/rsyslog.conf|sed 's/^[^/]*//'|xargs ls -lL


If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the ISSO, this is a finding.)
  desc 'fix', 'This fix is applicable to both Postfix and sendmail servers.
Remove the extended ACL from the file.
# setfacl --remove-all <log file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36160r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22442'
  tag rid: 'SV-37503r3_rule'
  tag stig_id: 'GEN004510'
  tag gtitle: 'GEN004510'
  tag fix_id: 'F-31411r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
