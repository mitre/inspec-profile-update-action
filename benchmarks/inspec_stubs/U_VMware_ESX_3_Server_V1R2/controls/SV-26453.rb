control 'SV-26453' do
  title "All files and directories contained in user's home directories must be group-owned by a group the home directory's owner is a member."
  desc "If a user's files are group-owned by a group where the user is not a member, unintended users may be able to access them."
  desc 'check', "Check the contents of user home directories for files group-owned by a group of which the home directory's owner is not a member.

1. List the user accounts.
# cut -d : -f 1/etc/passwd
2. For each user account, get a list of GIDs for files in the user's home directory.
# find < users home directory > -exec ls -lLd
3. Obtain the list of GIDs associated with the user's account.
# id < user name >
4. Check the GID lists. If there are GIDs in the file list not present in the user list, this is a finding."
  desc 'fix', "Change the group of a file not group-owned by a group where the home directory's owner is a member.
# chgrp [user's primary group] [file with bad group ownership]"
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-40624r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22351'
  tag rid: 'SV-26453r1_rule'
  tag stig_id: 'GEN001550'
  tag gtitle: 'GEN001550'
  tag fix_id: 'F-23645r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
