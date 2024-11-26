control 'SV-221725' do
  title 'The Oracle Linux operating system must be configured so that all files and directories have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', 'Verify all files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

# chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23440r419247_chk'
  tag severity: 'medium'
  tag gid: 'V-221725'
  tag rid: 'SV-221725r603260_rule'
  tag stig_id: 'OL07-00-020330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23429r419248_fix'
  tag 'documentable'
  tag legacy: ['SV-108293', 'V-99189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
