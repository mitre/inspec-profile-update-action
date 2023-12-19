control 'SV-35189' do
  title 'The system must use a remote syslog server (loghost).'
  desc 'A syslog server (loghost) receives syslog messages from one or more systems. This data can be used as an authoritative log source in the event a system is compromised and its local logs are suspect.'
  desc 'check', %q(A typical entry listing the loghost server should look similar to the following:
*.*	@example.com

Check the syslog configuration file for remote syslog servers. 
# cat /etc/syslog.conf | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | grep -v '^#' | grep "\@"

If no line information is returned, this is a finding.)
  desc 'fix', 'Edit the syslog configuration file and add an appropriate remote syslog server.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36624r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22455'
  tag rid: 'SV-35189r1_rule'
  tag stig_id: 'GEN005450'
  tag gtitle: 'GEN005450'
  tag fix_id: 'F-31991r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
