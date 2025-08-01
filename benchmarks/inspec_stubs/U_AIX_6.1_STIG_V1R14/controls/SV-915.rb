control 'SV-915' do
  title "All files and directories contained in user's home directories must have mode 0750 or less permissive."
  desc "Excessive permissions allow unauthorized access to user's files."
  desc 'check', "For each user in the /etc/passwd file, check for files and directories with a mode more permissive than 0750.

Procedure:
# find /<usershomedirectory> ! -fstype nfs ! \\( -name .login -o -name .cshrc -o -name .logout -o -name .profile -o -name .bash_profile -o -name .bashrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) \\( -perm -0001 -o -perm -0002 -o -perm -0004 -o -perm -0020 -o -perm -2000 -o -perm -4000 \\) -exec ls -ld {} \\;

If user's home directories contain files or directories more permissive than 0750, this is a finding."
  desc 'fix', "Change the mode of files and directories within user's home directories to 0750.

Procedure:
# chmod 0750 filename

Document all changes."
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-431r3_chk'
  tag severity: 'low'
  tag gid: 'V-915'
  tag rid: 'SV-915r2_rule'
  tag stig_id: 'GEN001560'
  tag gtitle: 'GEN001560'
  tag fix_id: 'F-1069r2_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
