control 'SV-38686' do
  title 'All system command files must not have extended ACLs.'
  desc "Restricting permissions will protect system command files from unauthorized modification. System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Verify all system command files have no extended ACLs.

# aclget /etc
# aclget /bin 
# aclget /usr/bin 
# aclget /usr/lbin 
# aclget /usr/ucb
# aclget /sbin 
# aclget /usr/sbin

If any of the command files have extended permissions enabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL(s) from the system command file(s) and set the extended permissions to disabled.

#acledit < command path >/< command file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36947r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22314'
  tag rid: 'SV-38686r1_rule'
  tag stig_id: 'GEN001210'
  tag gtitle: 'GEN001210'
  tag fix_id: 'F-32211r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
