control 'SV-253270' do
  title 'Only accounts responsible for the backup operations must be members of the Backup Operators group.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it. Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes. Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  desc 'check', 'Run "Computer Management".
Navigate to System Tools >> Local Users and Groups >> Groups.
Review the members of the Backup Operators group.

If the group contains no accounts, this is not a finding.

If the group contains any accounts, the accounts must be specifically for backup functions.

If the group contains any standard user accounts used for performing normal user tasks, this is a finding.'
  desc 'fix', 'Create separate accounts for backup operations for users with this privilege.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56723r828892_chk'
  tag severity: 'medium'
  tag gid: 'V-253270'
  tag rid: 'SV-253270r828894_rule'
  tag stig_id: 'WN11-00-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56673r828893_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
