control 'SV-204473' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all files and directories contained in local interactive user home directories have a mode of 0750 or less permissive.'
  desc 'If a local interactive user files have excessive permissions, unintended users may be able to access or modify them.'
  desc 'check', 'Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of "0750".

Check the mode of all non-initialization files in a local interactive user home directory with the following command:

Files that begin with a "." are excluded from this requirement.

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

# ls -lLR /home/smithj
-rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r-x--- 1 smithj smithj 231 Mar  5 17:06 file3

If any files are found with a mode more permissive than "0750", this is a finding.'
  desc 'fix', 'Set the mode on files and directories in the local interactive user home directory with the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

# chmod 0750 /home/smithj/<file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4597r88611_chk'
  tag severity: 'medium'
  tag gid: 'V-204473'
  tag rid: 'SV-204473r603261_rule'
  tag stig_id: 'RHEL-07-020680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4597r88612_fix'
  tag 'documentable'
  tag legacy: ['V-72027', 'SV-86651']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
