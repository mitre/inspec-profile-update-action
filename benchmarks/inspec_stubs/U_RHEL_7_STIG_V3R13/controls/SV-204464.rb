control 'SV-204464' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all files and directories have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', 'Verify all files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

# chgrp <group> <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4588r88584_chk'
  tag severity: 'medium'
  tag gid: 'V-204464'
  tag rid: 'SV-204464r853898_rule'
  tag stig_id: 'RHEL-07-020330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4588r88585_fix'
  tag 'documentable'
  tag legacy: ['V-72009', 'SV-86633']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
