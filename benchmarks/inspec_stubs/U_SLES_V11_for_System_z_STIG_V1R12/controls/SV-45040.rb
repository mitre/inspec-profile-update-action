control 'SV-45040' do
  title 'All files and directories contained in user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', 'For each user in the /etc/passwd file, check for files and directories with a mode more permissive than 0750.

Procedure:
# find /<usershomedirectory> ! -fstype nfs ! \\( -name .bashrc -o -name .bash_login -o -name .bash_logout -o -name .bash_profile -o -name .cshrc -o -name .kshrc -o -name .login -o -name .logout -o -name .profile -o -name .tcshrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) \\( -perm -0001 -o -perm -0002 -o -perm -0004 -o -perm -0020 -o -perm -2000 -o -perm -4000 \\) -exec ls -ld {} \\;

If user home directories contain files or directories more permissive than 0750, this is a finding.'
  desc 'fix', 'Change the mode of files and directories within user home directories to 0750.

Procedure:
# chmod 0750 filename

Document all changes.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42422r1_chk'
  tag severity: 'low'
  tag gid: 'V-915'
  tag rid: 'SV-45040r1_rule'
  tag stig_id: 'GEN001560'
  tag gtitle: 'GEN001560'
  tag fix_id: 'F-38452r1_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
