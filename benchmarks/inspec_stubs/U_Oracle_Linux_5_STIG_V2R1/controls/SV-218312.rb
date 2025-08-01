control 'SV-218312' do
  title 'All files and directories contained in interactive user home directories must be owned by the home directorys owner.'
  desc 'If users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.'
  desc 'check', "For each user in the /etc/passwd file, check for the presence of files and directories within the user's home directory not owned by the home directory owner.

Procedure:
# find /<usershomedirectory> ! -fstype nfs ! -user <username> ! \\( -name .bashrc -o -name .bash_login -o -name .bash_logout -o -name .bash_profile -o -name .cshrc -o -name .kshrc -o -name .login -o -name .logout -o -name .profile -o -name .tcshrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) -exec ls -ld {} \\;

If user home directories contain files or directories not owned by the home directory owner, this is a finding."
  desc 'fix', 'Change the ownership of files and directories in user home directories to the owner of the home directory. 

Procedure:
# chown accountowner filename'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19787r554273_chk'
  tag severity: 'low'
  tag gid: 'V-218312'
  tag rid: 'SV-218312r603259_rule'
  tag stig_id: 'GEN001540'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19785r554274_fix'
  tag 'documentable'
  tag legacy: ['V-914', 'SV-63831']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
