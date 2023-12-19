control 'SV-214007' do
  title 'SQL Server must generate audit records when privileges/permissions are deleted.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users. 
 
In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command.'
  desc 'check', 'Check the SQL Server Audit being used for the STIG compliant audit.  
 
If the following events are not included, this is a finding. 
 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 
 
Reference: 
https://msdn.microsoft.com/en-us/library/cc280663.aspx'
  desc 'fix', 'Add the following events to the SQL Server Audit that is being used for the STIG compliant audit. 
 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 
 
See the supplemental file "SQL 2016 Audit.sql". 

Reference: 
https://msdn.microsoft.com/en-us/library/cc280663.aspx'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15224r313804_chk'
  tag severity: 'medium'
  tag gid: 'V-214007'
  tag rid: 'SV-214007r754652_rule'
  tag stig_id: 'SQL6-D0-014100'
  tag gtitle: 'SRG-APP-000499-DB-000330'
  tag fix_id: 'F-15222r313805_fix'
  tag 'documentable'
  tag legacy: ['SV-93981', 'V-79275']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
