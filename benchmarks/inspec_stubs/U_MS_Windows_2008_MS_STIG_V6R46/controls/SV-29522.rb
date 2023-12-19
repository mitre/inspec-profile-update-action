control 'SV-29522' do
  title 'Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for the purpose of backup and restore.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  desc 'check', 'Review the Backup Operators group in Computer Management and/or Active Directory Users and Computers.  If the group contains no accounts, this is not a finding.  If the group does contain any accounts, this must be documented as specified below.

Documentable Explanation:  Any accounts that are members of the Backup Operators group must be documented with the IAO including application accounts.  Each Backup Operator will have a separate user account for backing up the system and for performing normal user tasks.'
  desc 'fix', 'Create the necessary documentation that identifies the members of this privileged group.  Ensure each member has a separate account for user duties and one for his privileged duties and the other requirements outlined in the manual check are met.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-13595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1168'
  tag rid: 'SV-29522r2_rule'
  tag gtitle: 'Members of the Backup Operators Group'
  tag fix_id: 'F-32r2_fix'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
