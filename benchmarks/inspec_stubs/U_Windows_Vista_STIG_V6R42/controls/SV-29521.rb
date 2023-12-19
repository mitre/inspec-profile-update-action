control 'SV-29521' do
  title 'Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for the purpose of backup and restore.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  desc 'check', 'Review the Backup Operators group in Computer Management.  If the group contains no accounts, this is not a finding.  If the group does contain any accounts, this must be documented as specified below.

Documentable Explanation:  Any accounts that are members of the Backup Operators group must be documented with the IAO including application accounts.  Each Backup Operator will have a separate user account for backing up the system and for performing normal user tasks.'
  desc 'fix', 'Ensure that each member has separate accounts for user tasks and for backup operator functions.  Create the necessary documentation that identifies the members of the Backup Operators group.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-51781r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1168'
  tag rid: 'SV-29521r2_rule'
  tag gtitle: 'Members of the Backup Operators Group'
  tag fix_id: 'F-53563r1_fix'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
