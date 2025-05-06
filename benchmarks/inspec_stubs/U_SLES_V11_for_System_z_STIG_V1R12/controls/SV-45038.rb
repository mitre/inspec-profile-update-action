control 'SV-45038' do
  title 'All files and directories contained in user home directories must be group-owned by a group of which the home directorys owner is a member.'
  desc "If a user's files are group-owned by a group of which the user is not a member, unintended users may be able to access them."
  desc 'check', "Check the contents of user home directories for files group-owned by a group of which the home directory's owner is not a member.
1. List the user accounts.
# cut -d : -f 1 /etc/passwd
2. For each user account, get a list of GIDs for files in the user's home directory.
# find ~username -printf %G\\\\n | sort | uniq
3. Obtain the list of GIDs where the user is a member.
# id -G username
4. Check the GID lists. If there are GIDs in the file list not present in the user list, this is a finding."
  desc 'fix', "Change the group of a file not group-owned by a group of which the home directory's owner is a member.
# chgrp <group with user as member> <file with bad group ownership>
Document all changes."
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42421r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22351'
  tag rid: 'SV-45038r1_rule'
  tag stig_id: 'GEN001550'
  tag gtitle: 'GEN001550'
  tag fix_id: 'F-38451r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
