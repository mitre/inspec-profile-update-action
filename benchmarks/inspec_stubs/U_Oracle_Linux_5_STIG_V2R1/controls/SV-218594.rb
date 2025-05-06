control 'SV-218594' do
  title 'The system must use a remote syslog server (loghost).'
  desc 'A syslog server (loghost) receives syslog messages from one or more systems.  This data can be used as an authoritative log source in the event a system is compromised and its local logs are suspect.'
  desc 'check', "Check the syslog configuration file for remote syslog servers.

Depending on what system is used for log processing either /etc/syslog.conf or /etc/rsyslog.conf will be the logging configuration file.

# grep '@' /etc/syslog.conf | grep -v '^#'

Or:

# grep '@' /etc/rsyslog.conf | grep -v '^#'

If no line is returned, this is a finding."
  desc 'fix', 'Edit the syslog or rsyslog configuration file and add an appropriate remote syslog server.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20069r562819_chk'
  tag severity: 'medium'
  tag gid: 'V-218594'
  tag rid: 'SV-218594r603259_rule'
  tag stig_id: 'GEN005450'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-20067r562820_fix'
  tag 'documentable'
  tag legacy: ['V-22455', 'SV-63501']
  tag cci: ['CCI-000136', 'CCI-001851']
  tag nist: ['AU-3 (2)', 'AU-4 (1)']
end
