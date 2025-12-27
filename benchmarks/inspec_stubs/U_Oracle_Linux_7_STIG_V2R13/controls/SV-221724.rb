control 'SV-221724' do
  title 'The Oracle Linux operating system must be configured so that all files and directories have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier (UID) as the UID of the un-owned files.'
  desc 'check', 'Verify all files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the "chown" command:

# chown <user> <file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23439r419244_chk'
  tag severity: 'medium'
  tag gid: 'V-221724'
  tag rid: 'SV-221724r603260_rule'
  tag stig_id: 'OL07-00-020320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23428r419245_fix'
  tag 'documentable'
  tag legacy: ['V-99187', 'SV-108291']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
