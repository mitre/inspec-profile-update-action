control 'SV-26745' do
  title 'The system must use a remote syslog server (log host).'
  desc 'A syslog server (log host) receives syslog messages from one or more systems.  This data can be used as an authoritative log source in the event a system is compromised and its local logs are suspect.'
  desc 'check', "Check the syslog configuration file for remote syslog servers.
# grep '@' /etc/syslog.conf | grep -v '^#'
If no line is returned, this is a finding."
  desc 'fix', 'Edit the syslog configuration file and add an appropriate remote syslog server.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22455'
  tag rid: 'SV-26745r1_rule'
  tag stig_id: 'GEN005450'
  tag gtitle: 'GEN005450'
  tag fix_id: 'F-23994r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
