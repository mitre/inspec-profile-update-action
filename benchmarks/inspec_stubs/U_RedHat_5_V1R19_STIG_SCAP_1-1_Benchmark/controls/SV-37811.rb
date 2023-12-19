control 'SV-37811' do
  title 'The system must use a remote syslog server (loghost).'
  desc 'A syslog server (loghost) receives syslog messages from one or more systems.  This data can be used as an authoritative log source in the event a system is compromised and its local logs are suspect.'
  desc 'fix', 'Edit the syslog or rsyslog configuration file and add an appropriate remote syslog server.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22455'
  tag rid: 'SV-37811r2_rule'
  tag stig_id: 'GEN005450'
  tag gtitle: 'GEN005450'
  tag fix_id: 'F-32277r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
