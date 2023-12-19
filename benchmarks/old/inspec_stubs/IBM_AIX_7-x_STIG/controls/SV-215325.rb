control 'SV-215325' do
  title 'All system command files must not have extended ACLs.'
  desc "Restricting permissions will protect system command files from unauthorized modification. System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Verify all system command files have no extended ACLs by running the following commands:
# aclget /etc 
# aclget /bin 
# aclget /usr/bin 
# aclget /usr/lbin 
# aclget /usr/ucb 
# aclget /sbin 
# aclget /usr/sbin 

If any of the command files have extended permissions enabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL(s) from the system command file(s) and set the extended permissions to disabled by running the following command: 
# acledit [command-path ]/[ command-file]'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16523r294426_chk'
  tag severity: 'medium'
  tag gid: 'V-215325'
  tag rid: 'SV-215325r508663_rule'
  tag stig_id: 'AIX7-00-003009'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-16521r294427_fix'
  tag 'documentable'
  tag legacy: ['V-91479', 'SV-101577']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
