control 'SV-226532' do
  title "All files and directories contained in interactive user's home directories must be owned by the home directory's owner."
  desc 'If users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.'
  desc 'check', "For each user in the /etc/passwd file, check for the presence of files and directories within the user's home directory not owned by the home directory owner or root.

Procedure:
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alLR DIR | more

OR

# find /<usershomedirectory> ! -fstype nfs ! -user <username>  -exec ls -ld {} \\; | more

If user's home directories contain files or directories not owned by the home directory owner or root, this is a finding."
  desc 'fix', "Change the ownership of files and directories in user's home directories to the owner of the home directory. 
Procedure: 
# chown accountowner filename 
OR
# find /<usershomedirectory> ! -fstype nfs ! -user <username> ! /( -name .login -o -name .cshrc -o -name .logout -o -name .profile -o -name .bash_profile -o -name .bashrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) -exec chown <username> {} \\;"
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36386r602761_chk'
  tag severity: 'low'
  tag gid: 'V-226532'
  tag rid: 'SV-226532r603265_rule'
  tag stig_id: 'GEN001540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36350r602762_fix'
  tag 'documentable'
  tag legacy: ['V-914', 'SV-39836']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
