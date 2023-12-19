control 'SV-35145' do
  title "All files and directories contained in user home directories must be group-owned by a group of which the home directory's owner is a member."
  desc "If a user's files are group-owned by a group of which the user is not a member, unintended users may be able to access them."
  desc 'check', %q(Check the contents of user home directories for files group-owned by a group of which the home directory's owner is not a member:

List the user accounts.
# cat /etc/passwd | cut -f 1,1 -d  ":" 

For each user account, get a list of GIDs for files in the user's home directory.
# find ~<username> | xargs ls -ldn | tr '\011' ' ' | tr -s ' ' | awk '{print $4, $NF}'

Obtain the list of GIDs associated with the user's account.
# id <username>
OR
# id -G <username>
OR
# cat /etc/group | grep <username> 

Check the GID lists. If there are GIDs in the file list not present in the user list, this is a finding.)
  desc 'fix', "Change the group of a file not group-owned by a group of which the home directory's owner is a member.
# chgrp [<username>'s primary group] [file with bad group ownership]"
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36548r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22351'
  tag rid: 'SV-35145r1_rule'
  tag stig_id: 'GEN001550'
  tag gtitle: 'GEN001550'
  tag fix_id: 'F-31914r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
