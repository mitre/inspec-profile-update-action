control 'SV-253099' do
  title 'All TOSS local files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', 'Verify all local files and directories on TOSS have a valid group with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

$ sudo find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding.

Note: Command may produce error messages from the /proc and /sys directories.'
  desc 'fix', 'Either remove all files and directories from TOSS that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

$ sudo chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56552r824967_chk'
  tag severity: 'medium'
  tag gid: 'V-253099'
  tag rid: 'SV-253099r824969_rule'
  tag stig_id: 'TOSS-04-040570'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56502r824968_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
