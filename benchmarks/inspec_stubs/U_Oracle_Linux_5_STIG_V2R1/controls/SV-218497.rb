control 'SV-218497' do
  title 'The system must log informational authentication data.'
  desc 'Monitoring and recording successful and unsuccessful logins assists in tracking unauthorized access to the system.'
  desc 'check', 'Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

Check /etc/syslog.conf or /etc/rsyslog.conf and verify the authpriv facility is logging both the "notice" and "info" priority messages.

Procedure:

For a given action all messages of a higher severity or "priority" are logged. The three lowest priorities in ascending order are "debug", "info" and "notice". A priority of "info" will include "notice". A priority of "debug" includes both "info" and "notice".

Enter/Input for syslog:

# grep "authpriv.debug" /etc/syslog.conf
# grep "authpriv.info" /etc/syslog.conf
# grep "authpriv\\.\\*" /etc/syslog.conf

Enter/Input for rsyslog:

# grep "authpriv.debug" /etc/rsyslog.conf
# grep "authpriv.info" /etc/rsyslog.conf
# grep "authpriv\\.\\*" /etc/rsyslog.conf

If an "authpriv.*", "authpriv.debug", or "authpriv.info" entry is not found, this is a finding.'
  desc 'fix', 'Edit /etc/syslog.conf or /etc/rsyslog.conf and add local log destinations for "authpriv.*", "authpriv.debug" or "authpriv.info".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19972r555689_chk'
  tag severity: 'medium'
  tag gid: 'V-218497'
  tag rid: 'SV-218497r603259_rule'
  tag stig_id: 'GEN003660'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19970r555690_fix'
  tag 'documentable'
  tag legacy: ['V-12004', 'SV-64229']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
