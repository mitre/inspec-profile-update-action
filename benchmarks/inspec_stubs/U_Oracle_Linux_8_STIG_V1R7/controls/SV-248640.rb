control 'SV-248640' do
  title 'All OL 8 local interactive user home directory files must have mode "0750" or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  desc 'check', 'Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of "0750".

Files that begin with a "." are excluded from this requirement.

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

$ sudo ls -lLR /home/smithj
-rwxr-x--- 1 smithj smithj 18 Mar 5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar 5 17:06 file2
-rw-r-x--- 1 smithj smithj 231 Mar 5 17:06 file3

If any files or directories are found with a mode more permissive than "0750", this is a finding.'
  desc 'fix', 'Set the mode on files and directories in the local interactive user home directory with the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

$ sudo chmod 0750 /home/smithj/<file or directory>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52074r779484_chk'
  tag severity: 'medium'
  tag gid: 'V-248640'
  tag rid: 'SV-248640r779486_rule'
  tag stig_id: 'OL08-00-010731'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52028r779485_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
