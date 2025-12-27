control 'SV-226531' do
  title "User's home directories must not have extended ACLs."
  desc "Excessive permissions on home directories allow unauthorized access to user's files."
  desc 'check', %q(Verify user's home directories have no extended ACLs.

# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld 

If the permissions include a "+", the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [user home directory with extended ACL]'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28692r482981_chk'
  tag severity: 'low'
  tag gid: 'V-226531'
  tag rid: 'SV-226531r603265_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28680r482982_fix'
  tag 'documentable'
  tag legacy: ['V-22350', 'SV-26451']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
