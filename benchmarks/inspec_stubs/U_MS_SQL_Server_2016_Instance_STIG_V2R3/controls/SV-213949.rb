control 'SV-213949' do
  title 'SQL Server must protect its audit features from unauthorized removal.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data. 
 
Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the deletion of audit tools.  SQL Server is an application that does provide access to audit data. 
 
Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', "Check the server documentation for a list of approved users with access to SQL Server Audits. 
 
To alter, or drop a server audit, principals require the ALTER ANY SERVER AUDIT or the CONTROL SERVER permission. 
 
Review the SQL Server permissions granted to principals. Look for permissions ALTER ANY SERVER AUDIT, ALTER ANY DATABASE AUDIT, CONTROL SERVER: 
 
SELECT login.name, perm.permission_name, perm.state_desc 
FROM sys.server_permissions perm 
JOIN sys.server_principals login 
ON perm.grantee_principal_id = login.principal_id 
WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT') 
and login.name not like '##MS_%'; 
 
If unauthorized accounts have these privileges, this is a finding."
  desc 'fix', 'Remove audit-related permissions from individuals and roles not authorized to have them. 
 
USE master;   
DENY [ALTER ANY SERVER AUDIT] TO [User];   
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15166r313630_chk'
  tag severity: 'medium'
  tag gid: 'V-213949'
  tag rid: 'SV-213949r617437_rule'
  tag stig_id: 'SQL6-D0-006400'
  tag gtitle: 'SRG-APP-000123-DB-000204'
  tag fix_id: 'F-15164r313631_fix'
  tag 'documentable'
  tag legacy: ['SV-93867', 'V-79161']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
