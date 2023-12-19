control 'SV-235029' do
  title 'All SUSE operating system files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', 'Verify all SUSE operating system files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

> sudo find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the SUSE operating system that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

> sudo chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38217r619356_chk'
  tag severity: 'medium'
  tag gid: 'V-235029'
  tag rid: 'SV-235029r622137_rule'
  tag stig_id: 'SLES-15-040410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38180r619357_fix'
  tag 'documentable'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
