control 'SV-214008' do
  title 'SQL Server must generate audit records when unsuccessful attempts to delete privileges/permissions occur.'
  desc 'Failed attempts to change the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized attempts to elevate or restrict privileges could go undetected.  
 
In an SQL environment, deleting permissions is typically done via the REVOKE or DENY command.  
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
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
  tag check_id: 'C-15225r313807_chk'
  tag severity: 'medium'
  tag gid: 'V-214008'
  tag rid: 'SV-214008r617437_rule'
  tag stig_id: 'SQL6-D0-014200'
  tag gtitle: 'SRG-APP-000499-DB-000331'
  tag fix_id: 'F-15223r313808_fix'
  tag 'documentable'
  tag legacy: ['SV-93983', 'V-79277']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
