control 'SV-221733' do
  title 'The Oracle Linux operating system must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.'
  desc "If a local interactive user's files are group-owned by a group of which the user is not a member, unintended users may be able to access them."
  desc 'check', %q(Verify all files and directories in a local interactive user home directory are group-owned by a group of which the user is a member.

Check the group owner of all files and directories in a local interactive user's home directory with the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

# ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
-rw-r--r-- 1 smithj sa 231 Mar 5 17:06 file3

If any files are found with an owner different than the group home directory user, check to see if the user is a member of that group with the following command:

# grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj 
smithj:x:521:smithj

If the user is not a member of a group that group-owns file(s) in a local interactive user's home directory, this is a finding.)
  desc 'fix', %q(Change the group of a local interactive user's files and directories to a group that the interactive user is a member of. To change the group owner of a local interactive user's files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

# chgrp users /home/smithj/<file>)
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23448r419271_chk'
  tag severity: 'medium'
  tag gid: 'V-221733'
  tag rid: 'SV-221733r603260_rule'
  tag stig_id: 'OL07-00-020670'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23437r419272_fix'
  tag 'documentable'
  tag legacy: ['V-99205', 'SV-108309']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
