control 'SV-53920' do
  title 'SQL Server must be protected from unauthorized access by developers.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Developers granted elevated database and/or operating system privileges on production databases can affect the operation and/or security of the database system. Operating system and database privileges assigned to developers on production systems should not be allowed.'
  desc 'check', "Check the list of SQL Server users against the list of developer accounts by running the following SQL Server query:

SELECT name AS 'Account Name'
     , create_date AS 'Account Create Date'
     , LOGINPROPERTY(name, 'PasswordLastSetTime') AS 'Password Last Set on'
FROM sys.server_principals
WHERE NOT TYPE IN ('C', 'R', 'U') 
AND NOT name IN ('##MS_PolicyEventProcessingLogin##', '##MS_PolicyTsqlExecutionLogin##')
AND sid <> CONVERT(VARBINARY(85), 0x01) -- no 'sa' account
AND is_disabled <> 1
ORDER BY name; 

For each developer account found on a production machine, verify if the developer account can change or alter database objects or data in the production database. If any developer account can change or alter database objects or data in a production database, this is a finding."
  desc 'fix', "Remove unnecessary developer accounts from SQL Server instances hosting only production databases, by running the following SQL script:

USE master
DROP LOGIN <'account name'>"
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47932r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41395'
  tag rid: 'SV-53920r4_rule'
  tag stig_id: 'SQL2-00-009200'
  tag gtitle: 'SRG-APP-000062-DB-000014'
  tag fix_id: 'F-46820r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002220']
  tag nist: ['AC-5 b']
end
