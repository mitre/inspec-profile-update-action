control 'SV-230326' do
  title 'All RHEL 8 local files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the un-owned files.'
  desc 'check', 'Verify all local files and directories on RHEL 8 have a valid owner with the following command:

Note: The value after -fstype must be replaced with the filesystem type.  XFS is used as an example.

$ sudo find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding.

Note: Command may produce error messages from the /proc and /sys directories.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on RHEL 8 with the "chown" command:

$ sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32995r567724_chk'
  tag severity: 'medium'
  tag gid: 'V-230326'
  tag rid: 'SV-230326r627750_rule'
  tag stig_id: 'RHEL-08-010780'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32970r567725_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
