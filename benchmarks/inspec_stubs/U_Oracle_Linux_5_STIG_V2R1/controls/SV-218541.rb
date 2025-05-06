control 'SV-218541' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20016r562738_chk'
  tag severity: 'medium'
  tag gid: 'V-218541'
  tag rid: 'SV-218541r603259_rule'
  tag stig_id: 'GEN004480'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20014r562739_fix'
  tag 'documentable'
  tag legacy: ['V-837', 'SV-63751']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
