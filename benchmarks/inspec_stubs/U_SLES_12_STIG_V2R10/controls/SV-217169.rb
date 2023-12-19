control 'SV-217169' do
  title 'All SUSE operating system files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', 'Verify all SUSE operating system files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the SUSE operating system that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

# sudo chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18397r369663_chk'
  tag severity: 'medium'
  tag gid: 'V-217169'
  tag rid: 'SV-217169r854097_rule'
  tag stig_id: 'SLES-12-010700'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18395r369664_fix'
  tag 'documentable'
  tag legacy: ['SV-91889', 'V-77193']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
