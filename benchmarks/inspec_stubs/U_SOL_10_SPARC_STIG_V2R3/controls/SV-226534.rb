control 'SV-226534' do
  title "All files and directories contained in user's home directories must have mode 0750 or less permissive."
  desc "Excessive permissions allow unauthorized access to user's files."
  desc 'check', "For each user in the /etc/passwd file, check for files and directories with a mode more permissive than 0750.

Procedure: 
# find /<usershomedirectory> ! -fstype nfs  \\( -perm -0001 -o -perm -0002 -o -perm -0004 -o -perm -0020 -o -perm -2000 -o -perm -4000 \\) -exec ls -ld {} \\; 
If user's home directories contain files or directories more permissive than 0750, this is a finding."
  desc 'fix', "Change the mode of files and directories within user's home directories to 0750.

Procedure:
# chmod 0750 filename

Document all changes."
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28695r482996_chk'
  tag severity: 'low'
  tag gid: 'V-226534'
  tag rid: 'SV-226534r603265_rule'
  tag stig_id: 'GEN001560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28683r482997_fix'
  tag 'documentable'
  tag legacy: ['SV-39840', 'V-915']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
