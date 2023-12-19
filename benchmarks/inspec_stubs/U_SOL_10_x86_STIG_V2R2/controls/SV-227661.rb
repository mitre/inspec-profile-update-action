control 'SV-227661' do
  title 'All files and directories contained in user home directories must not have extended ACLs.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', %q(Check the contents of interactive user's home directories (99 < UID < 60000) for files with extended ACLs. 

# ls -alLR < users home dir >

If the permissions include a "+", the file has an extended ACL and this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [user file with extended ACL]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29823r488549_chk'
  tag severity: 'medium'
  tag gid: 'V-227661'
  tag rid: 'SV-227661r603266_rule'
  tag stig_id: 'GEN001570'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29811r488550_fix'
  tag 'documentable'
  tag legacy: ['V-22352', 'SV-26456']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
