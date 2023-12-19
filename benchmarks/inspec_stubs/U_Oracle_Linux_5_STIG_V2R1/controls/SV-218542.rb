control 'SV-218542' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20017r562741_chk'
  tag severity: 'medium'
  tag gid: 'V-218542'
  tag rid: 'SV-218542r603259_rule'
  tag stig_id: 'GEN004500'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20015r562742_fix'
  tag 'documentable'
  tag legacy: ['V-838', 'SV-63753']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
