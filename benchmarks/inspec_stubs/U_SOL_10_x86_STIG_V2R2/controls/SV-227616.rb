control 'SV-227616' do
  title 'All system command files must not have extended ACLs.'
  desc "Restricting permissions will protect system command files from unauthorized modification.  System command files include files present in directories used by the operating system for storing default system executables and files present in directories included in the system's default executable search paths."
  desc 'check', 'Verify all system command files have no extended ACLs.
# ls -lL /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file. 
# chmod A- [file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29778r488405_chk'
  tag severity: 'medium'
  tag gid: 'V-227616'
  tag rid: 'SV-227616r603266_rule'
  tag stig_id: 'GEN001210'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-29766r488406_fix'
  tag 'documentable'
  tag legacy: ['V-22314', 'SV-26365']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
