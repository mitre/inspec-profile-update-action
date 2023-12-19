control 'SV-235028' do
  title 'All SUSE operating system files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier (UID) as the UID of the unowned files.'
  desc 'check', 'Verify that all SUSE operating system files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

> sudo find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the SUSE operating system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the "chown" command:

> sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38216r619353_chk'
  tag severity: 'medium'
  tag gid: 'V-235028'
  tag rid: 'SV-235028r622137_rule'
  tag stig_id: 'SLES-15-040400'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38179r619354_fix'
  tag 'documentable'
  tag cci: ['CCI-001230']
  tag nist: ['SI-2 d']
end
