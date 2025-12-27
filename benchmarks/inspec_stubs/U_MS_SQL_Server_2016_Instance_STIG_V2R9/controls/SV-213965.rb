control 'SV-213965' do
  title 'Contained databases must use Windows principals.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001).  Native DBMS authentication may be used only when circumstances make it unavoidable; and must be documented and AO-approved. 
 
The DoD standard for authentication is DoD-approved PKI certificates.  Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval. 
 
In such cases, the DoD standards for password complexity and lifetime must be implemented.  DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so.  For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', "Execute the following query to determine if Contained Databases are used: 
 
SELECT * FROM sys.databases WHERE containment = 1 
 
If any records are returned. Check the server documentation for a list of authorized contained database users. Ensure contained database users are not using SQL Authentication. 
 
EXEC sp_MSforeachdb 'USE [?]; SELECT DB_NAME() AS DatabaseName, * FROM sys.database_principals WHERE authentication_type = 2' 
 
If any records are returned, this is a finding."
  desc 'fix', 'Configure the SQL Server contained databases to have users originating from Windows principals. Remove any users not created from Windows principals.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15182r313678_chk'
  tag severity: 'medium'
  tag gid: 'V-213965'
  tag rid: 'SV-213965r879601_rule'
  tag stig_id: 'SQL6-D0-008000'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-15180r313679_fix'
  tag 'documentable'
  tag legacy: ['SV-93899', 'V-79193']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
