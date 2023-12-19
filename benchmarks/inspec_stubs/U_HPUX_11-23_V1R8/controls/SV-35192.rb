control 'SV-35192' do
  title 'The system must only use remote syslog servers (log hosts) justified and documented using site-defined procedures.'
  desc "If a remote log host is in use and it has not been justified and documented with the IAO, sensitive information could be obtained by unauthorized users without the SA's knowledge. A remote log host is any host to which the system is sending syslog messages over a network."
  desc 'check', %q(Examine the syslog.conf file for any references to remote log hosts.
# cat /etc/syslog.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep "\@"

Destinations beginning with the @ symbol represent log hosts. If the log host name is a local alias such as loghost, consult the /etc/hosts or other name databases as necessary to obtain the canonical name or address for the log host. Determine if the host referenced is a log host documented using site-defined procedures. If an undocumented log host is referenced, this is a finding.)
  desc 'fix', 'Remove or document the referenced undocumented log host.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35037r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4395'
  tag rid: 'SV-35192r1_rule'
  tag stig_id: 'GEN005460'
  tag gtitle: 'GEN005460'
  tag fix_id: 'F-30328r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
