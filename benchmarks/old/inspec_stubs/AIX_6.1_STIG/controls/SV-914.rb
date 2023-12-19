control 'SV-914' do
  title "All files and directories contained in interactive user's home directories must be owned by the home directory's owner."
  desc 'If users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.'
  desc 'check', "For each user in the /etc/passwd file, check for the presence of files and directories within the user's home directory not owned by the home directory owner.

Procedure:
# find /<usershomedirectory> ! -fstype nfs ! -user <username> ! \\( -name .login -o -name .cshrc -o -name .logout -o -name .profile -o -name .bash_profile -o -name .bashrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) -exec ls -ld {} \\;

If user's home directories contain files or directories not owned by the home directory owner, this is a finding."
  desc 'fix', "Change the ownership of files and directories in user's home directories to the owner of the home directory. 

Procedure:
# chown accountowner filename   
OR
# find /<usershomedirectory> ! -fstype nfs ! -user <username> ! /( -name .login -o -name .cshrc -o -name .logout -o -name .profile -o -name .bash_profile -o -name .bashrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) -exec chown <username> {} \\;"
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-405r3_chk'
  tag severity: 'low'
  tag gid: 'V-914'
  tag rid: 'SV-914r2_rule'
  tag stig_id: 'GEN001540'
  tag gtitle: 'GEN001540'
  tag fix_id: 'F-1068r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
