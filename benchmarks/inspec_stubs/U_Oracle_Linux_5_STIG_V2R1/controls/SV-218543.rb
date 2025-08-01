control 'SV-218543' do
  title 'The SMTP service log file must not have an extended ACL.'
  desc 'If the SMTP service log file has an extended ACL, unauthorized users may be allowed to access or to modify the log file.'
  desc 'check', %q(Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Examine /etc/syslog.conf or /etc/rsyslog.conf and determine the log file(s) receiving logs for "mail.crit", "mail.debug", mail.*, or "*.crit".

Procedure:

This check is applicable to both Postfix or sendmail servers.

Check the permissions on these log files.

Identify any log files configured for "*.crit" and the "mail" service (excluding mail.none) and at any severity level.

For syslog:

# egrep "(\*.crit|mail\.[^n][^/]*)" /etc/syslog.conf|sed 's/^[^/]*//'|xargs ls -lL

For rsyslog:

# egrep "(\*.crit|mail\.[^n][^/]*)" /etc/rsyslog.conf|sed 's/^[^/]*//'|xargs ls -lL

If the permissions include a '+', the file has an extended ACL.

If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'This fix is applicable to both Postfix and sendmail servers.

Remove the extended ACL from the file.

# setfacl --remove-all <log file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20018r562744_chk'
  tag severity: 'medium'
  tag gid: 'V-218543'
  tag rid: 'SV-218543r603259_rule'
  tag stig_id: 'GEN004510'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20016r562745_fix'
  tag 'documentable'
  tag legacy: ['V-22442', 'SV-63755']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
