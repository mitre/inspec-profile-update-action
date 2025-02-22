control 'SV-215312' do
  title 'AIX must implement a remote syslog server that is documented using site-defined procedures.'
  desc 'If a remote log host is in use and it has not been justified and documented, sensitive information could be obtained by unauthorized users without the administrator’s knowledge.

'
  desc 'check', %q(Examine the "syslog.conf" file for any references to remote log hosts using command: 

# grep -v "^#" /etc/syslog.conf | grep '@' 
@<loghost>

Ask ISSO/SA for a list of valid remote syslog servers justified and documented using site-defined procedures.

Destination locations beginning with "@" represent log hosts. If the log host name is a local alias, such as log host, consult the "/etc/hosts" or other name databases as necessary to obtain the canonical name or address for the log host. Determine if the host referenced is a syslog host documented using site-defined procedures. 

If a loghost is not defined, not documented, or is commented out this is a finding.)
  desc 'fix', 'Edit the /etc/syslog.conf file to include a documented and approved remote log host.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16510r294387_chk'
  tag severity: 'medium'
  tag gid: 'V-215312'
  tag rid: 'SV-215312r853479_rule'
  tag stig_id: 'AIX7-00-002131'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16508r294388_fix'
  tag satisfies: ['SRG-OS-000480-GPOS-00227', 'SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag legacy: ['V-91657', 'SV-101755']
  tag cci: ['CCI-000366', 'CCI-001851']
  tag nist: ['CM-6 b', 'AU-4 (1)']
end
