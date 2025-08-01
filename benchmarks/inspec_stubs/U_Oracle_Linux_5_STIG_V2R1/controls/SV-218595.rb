control 'SV-218595' do
  title 'The system must only use remote syslog servers (log hosts) that is justified and documented using site-defined procedures.'
  desc "If a remote log host is in use and it has not been justified and documented with the IAO, sensitive information could be obtained by unauthorized users without the SA's knowledge.  A remote log host is any host to which the system is sending syslog messages over a network."
  desc 'check', %q(Examine the syslog.conf or rsyslog.conf file for any references to remote log hosts.

# grep -v "^#" /etc/syslog.conf | grep '@'

Or:

# grep -v "^#" /etc/rsyslog.conf | grep '@'

Destination locations beginning with an '@' represent log hosts.

If the log host name is a local alias such as "loghost", consult the /etc/hosts or other name databases as necessary to obtain the canonical name or address for the log host.

Determine if the host referenced is a log host documented using site-defined procedures.

If an undocumented log host is referenced, this is a finding.)
  desc 'fix', 'Remove or document the referenced undocumented log host.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20070r562822_chk'
  tag severity: 'medium'
  tag gid: 'V-218595'
  tag rid: 'SV-218595r603259_rule'
  tag stig_id: 'GEN005460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20068r562823_fix'
  tag 'documentable'
  tag legacy: ['V-4395', 'SV-63507']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
