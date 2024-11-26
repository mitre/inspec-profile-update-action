control 'SV-227889' do
  title 'The system must use a remote syslog server (log host).'
  desc 'A syslog server (log host) receives syslog messages from one or more systems.  This data can be used as an authoritative log source in the event a system is compromised and its local logs are suspect.'
  desc 'check', "Check the syslog configuration file for remote syslog servers.
# grep '@' /etc/syslog.conf | grep -v '^#'
If no line is returned, this is a finding."
  desc 'fix', 'Edit the syslog configuration file and add an appropriate remote syslog server.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30051r490066_chk'
  tag severity: 'medium'
  tag gid: 'V-227889'
  tag rid: 'SV-227889r603266_rule'
  tag stig_id: 'GEN005450'
  tag gtitle: 'SRG-OS-000215'
  tag fix_id: 'F-30039r490067_fix'
  tag 'documentable'
  tag legacy: ['V-22455', 'SV-26745']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
