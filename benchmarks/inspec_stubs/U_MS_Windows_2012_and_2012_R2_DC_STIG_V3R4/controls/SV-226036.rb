control 'SV-226036' do
  title 'Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  desc 'check', 'If no accounts are members of the Backup Operators group, this is NA.

Verify users with accounts in the Backup Operators group have a separate user account for backup functions and for performing normal user tasks.  If users with accounts in the Backup Operators group do not have separate accounts for backup functions and standard user functions, this is a finding.'
  desc 'fix', 'Ensure each member of the Backup Operators group has separate accounts for backup functions and standard user functions.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27738r475431_chk'
  tag severity: 'medium'
  tag gid: 'V-226036'
  tag rid: 'SV-226036r794375_rule'
  tag stig_id: 'WN12-00-000009-02'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27726r475432_fix'
  tag 'documentable'
  tag legacy: ['SV-52157', 'V-40198']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
