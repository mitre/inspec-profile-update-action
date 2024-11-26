control 'SV-38497' do
  title "All files and directories contained in interactive user home directories must be owned by the home directory's owner."
  desc 'If users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.'
  desc 'check', %q(For each user in the /etc/passwd file, check for the presence of files and directories within the user's home directory that are not owned by the home directory owner.
# find /<usershomedirectory> ! -fstype nfs ! -user <username> ! \( -name .login -o -name .cshrc -o -name .logout -o -name .profile -o -name .bash_profile -o -name .bashrc -o -name .env -o -name .dtprofile -o -name .dispatch -o -name .emacs -o -name .exrc \\) -exec ls -ld {} \;

Or

# ls -lLR `cat /etc/passwd | cut -f 6,6 -d ":"` | more
If user home directories contain files or directories not owned by the home directory owner, this is a finding.)
  desc 'fix', 'Change the ownership of files and directories in user home directories to the owner of the home directory. 

Procedure:
# chown <account-owner> <filename>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36340r5_chk'
  tag severity: 'low'
  tag gid: 'V-914'
  tag rid: 'SV-38497r1_rule'
  tag stig_id: 'GEN001540'
  tag gtitle: 'GEN001540'
  tag fix_id: 'F-31595r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
