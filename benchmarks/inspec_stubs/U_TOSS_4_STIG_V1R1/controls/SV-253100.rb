control 'SV-253100' do
  title 'All TOSS local files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the un-owned files.'
  desc 'check', 'Verify all local files and directories on TOSS have a valid owner with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

$ sudo find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding.

Note: Command may produce error messages from the /proc and /sys directories.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on TOSS with the "chown" command:

$ sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56553r824970_chk'
  tag severity: 'medium'
  tag gid: 'V-253100'
  tag rid: 'SV-253100r824972_rule'
  tag stig_id: 'TOSS-04-040580'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56503r824971_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
