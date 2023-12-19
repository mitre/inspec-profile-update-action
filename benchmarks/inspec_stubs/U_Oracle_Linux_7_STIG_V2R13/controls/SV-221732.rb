control 'SV-221732' do
  title 'The Oracle Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the un-owned files.'
  desc 'check', %q(Verify all files and directories in a local interactive user's home directory have a valid owner.

Check the owner of all files and directories in a local interactive user's home directory with the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

$ sudo ls -lLR /home/smithj
-rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar 5 17:06 file3

If any files or directories are found without an owner, this is a finding.)
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on OL 7 with the "chown" command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj".

$ sudo chown smithj /home/smithj/<file or directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23447r744077_chk'
  tag severity: 'medium'
  tag gid: 'V-221732'
  tag rid: 'SV-221732r744079_rule'
  tag stig_id: 'OL07-00-020660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23436r744078_fix'
  tag 'documentable'
  tag legacy: ['SV-108307', 'V-99203']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
