control 'SV-25216' do
  title 'Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  desc 'check', 'Review the Backup Operators group in Computer Management.

If the group contains any accounts, this must be documented with the ISSO.

Any accounts that are members of the Backup Operators group must be documented, including application accounts.  Users with accounts in the Backup Operators group will have a separate user account for backup functions and for performing normal user tasks.

If the group contains no accounts, this is not a finding.

If any of the following conditions are true, this is a finding:

-Each Backup Operator does not have a unique userid dedicated to the backup function.
-Each Backup Operator does not have a separate account for normal user tasks.
-The ISSO does not maintain a list of users belonging to the Backup Operators group.'
  desc 'fix', 'Create the necessary documentation that identifies the members of the Backup Operators group, to be maintained with the ISSO.

Create separate accounts for backup operations for users with this privilege.

Create separate accounts for normal user functions for users with this privilege.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62067r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1168'
  tag rid: 'SV-25216r2_rule'
  tag gtitle: 'Members of the Backup Operators Group'
  tag fix_id: 'F-66965r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
