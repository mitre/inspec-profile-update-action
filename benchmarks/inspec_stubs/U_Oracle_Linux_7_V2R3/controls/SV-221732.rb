control 'SV-221732' do
  title 'The Oracle Linux operating system must be configured so that all files and directories contained in local interactive user home directories are owned by the owner of the home directory.'
  desc 'If local interactive users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.'
  desc 'check', %q(Verify all files and directories in a local interactive user's home directory are owned by the user.

Check the owner of all files and directories in a local interactive user's home directory with the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

# ls -lLR /home/smithj
-rw-r--r-- 1 smithj smithj 18 Mar 5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar 5 17:06 file2
-rw-r--r-- 1 smithj smithj 231 Mar 5 17:06 file3

If any files are found with an owner different than the home directory user, this is a finding.)
  desc 'fix', %q(Change the owner of a local interactive user's files and directories to that owner. To change the owner of a local interactive user's files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj".

# chown smithj /home/smithj/<file or directory>)
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23447r419268_chk'
  tag severity: 'medium'
  tag gid: 'V-221732'
  tag rid: 'SV-221732r603260_rule'
  tag stig_id: 'OL07-00-020660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23436r419269_fix'
  tag 'documentable'
  tag legacy: ['SV-108307', 'V-99203']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
