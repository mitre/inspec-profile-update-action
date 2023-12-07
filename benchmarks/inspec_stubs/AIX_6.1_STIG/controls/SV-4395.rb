control 'SV-4395' do
  title 'The system must only use remote syslog servers (log hosts) justified and documented using site-defined procedures.'
  desc "If a remote log host is in use and it has not been justified and documented with the IAO, sensitive information could be obtained by unauthorized users without the SA's knowledge.  A remote log host is any host to which the system is sending syslog messages over a network."
  desc 'check', %q(Examine the syslog.conf file for any references to remote log hosts.
# grep -v "^#" /etc/syslog.conf | grep '@'
Destination locations beginning with an @ represent log hosts. If the log host name is a local alias, such as log host, consult the /etc/hosts or other name databases as necessary to obtain the canonical name or address for the log host. Determine if the host referenced is a log host documented using site-defined procedures. If an undocumented log host is referenced, this is a finding.)
  desc 'fix', 'Remove, replace, or document the referenced undocumented log host.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8274r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4395'
  tag rid: 'SV-4395r2_rule'
  tag stig_id: 'GEN005460'
  tag gtitle: 'GEN005460'
  tag fix_id: 'F-4306r3_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
