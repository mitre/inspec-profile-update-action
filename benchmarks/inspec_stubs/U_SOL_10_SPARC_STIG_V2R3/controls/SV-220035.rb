control 'SV-220035' do
  title "Local initialization files must be group-owned by the user's primary group or root."
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "Check user home directories for local initialization files group-owned by a group other than the user's primary group or root.
1. List user accounts and their primary GID.
# cut -d : -f 1,4 /etc/passwd
 
2. Check local initialization files for each user.
# ls -al /<usershomedirectory>/.login
# ls -al /<usershomedirectory>/.cshrc
# ls -al /<usershomedirectory>/.logout
# ls -al /<usershomedirectory>/.profile
# ls -al /<usershomedirectory>/.bash_profile
# ls -al /<usershomedirectory>/.bashrc
# ls -al /<usershomedirectory>/.bash_logout
# ls -al /<usershomedirectory>/.env
# ls -al /<usershomedirectory>/.dtprofile
# ls -al /<usershomedirectory>/.dispatch
# ls -al /<usershomedirectory>/.emacs
# ls -al /<usershomedirectory>/.exrc
# find /<usershomedirectory>/.dt ! -fstype nfs ! -group <primary_group> -exec ls -ld {} \\;
 
3. If any file is not group-owned by root or the user's primary GID, this is a finding."
  desc 'fix', "Change the group-owner of the local initialization file to the user's primary group, or root.
# chgrp [USER's primary GID] ~USER/[local initialization file]"
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21744r483068_chk'
  tag severity: 'medium'
  tag gid: 'V-220035'
  tag rid: 'SV-220035r603265_rule'
  tag stig_id: 'GEN001870'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21743r483069_fix'
  tag 'documentable'
  tag legacy: ['SV-37101', 'V-22361']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
