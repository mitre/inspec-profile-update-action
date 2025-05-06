control 'SV-217168' do
  title 'All SUSE operating system files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier (UID) as the UID of the unowned files.'
  desc 'check', 'Verify that all SUSE operating system files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

# find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the SUSE operating system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the "chown" command:

# sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18396r369660_chk'
  tag severity: 'medium'
  tag gid: 'V-217168'
  tag rid: 'SV-217168r603262_rule'
  tag stig_id: 'SLES-12-010690'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18394r369661_fix'
  tag 'documentable'
  tag legacy: ['SV-91883', 'V-77187']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
