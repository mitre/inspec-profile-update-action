control 'SV-226473' do
  title "The root account's home directory must not have an extended ACL."
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', %q(Verify the root account's home directory has no extended ACL.
# ls -ld ~root
If the permissions include a "+", the directory has an extended ACL and this is a finding.)
  desc 'fix', 'Remove the extended ACL from the directory.
# chmod A- ~root'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28634r482801_chk'
  tag severity: 'medium'
  tag gid: 'V-226473'
  tag rid: 'SV-226473r603265_rule'
  tag stig_id: 'GEN000930'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28622r482802_fix'
  tag 'documentable'
  tag legacy: ['V-22309', 'SV-26353']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
