control 'SV-227657' do
  title "User's home directories must not have extended ACLs."
  desc "Excessive permissions on home directories allow unauthorized access to user's files."
  desc 'check', %q(Verify user's home directories have no extended ACLs.

# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld 

If the permissions include a "+", the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [user home directory with extended ACL]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29819r488531_chk'
  tag severity: 'low'
  tag gid: 'V-227657'
  tag rid: 'SV-227657r603266_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29807r488532_fix'
  tag 'documentable'
  tag legacy: ['V-22350', 'SV-26451']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
