control 'SV-82285' do
  title 'Audit tools used in, or in conjunction with, SQL Server must be protected from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user has in order to make access decisions regarding access to the audit tools. SQL Server is an application that does provide access to audit data. 

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', %q(Check the server documentation for a list of approved users with access to SQL Server Audits. 

To create, alter, or drop a server audit, principals require the "ALTER ANY SERVER AUDIT" or the "CONTROL SERVER" permission. To view an Audit log requires the "CONTROL SERVER" permission. To use Profiler, "ALTER TRACE" is required. 

Review the SQL Server permissions granted to principals. Look for permissions "ALTER ANY SERVER AUDIT", "ALTER ANY DATABASE AUDIT", "CONTROL SERVER", and "ALTER TRACE": 

SELECT login.name, perm.permission_name, perm.state_desc 
FROM sys.server_permissions perm     -- or STIG.server_permissions 
JOIN sys.server_principals login 
ON perm.grantee_principal_id = login.principal_id 
WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE') 
and login.name not like '##MS_%'; 

If unauthorized accounts have these privileges, this is a finding.)
  desc 'fix', 'Remove audit-related permissions from individuals and roles not authorized to have them.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2014'
  tag check_id: 'C-68363r3_chk'
  tag severity: 'medium'
  tag gid: 'V-67795'
  tag rid: 'SV-82285r2_rule'
  tag stig_id: 'SQL4-00-013900'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-73911r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
