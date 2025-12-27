control 'SV-213960' do
  title 'Access to linked servers must be disabled or restricted, unless specifically required and approved.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Applications must adhere to the principles of least functionality by providing only essential capabilities. SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system. A linked server allows for access to distributed, heterogeneous queries against OLE DB data sources. After a linked server is created, distributed queries can be run against this server, and queries can join tables from more than one data source. If the linked server is defined as an instance of SQL Server, remote stored procedures can be executed.  This access may be exploited by malicious users who have compromised the integrity of the SQL Server.'
  desc 'check', 'A linked server allows for access to distributed, heterogeneous queries against OLE DB data sources. After a linked server is created, distributed queries can be run against this server, and queries can join tables from more than one data source. If the linked server is defined as an instance of SQL Server, remote stored procedures can be executed. 
 
To obtain a list of linked servers, execute the following command:  
 
EXEC sp_linkedservers;  
 
Review the system documentation to determine whether the linked servers listed are required and approved. If it is not approved, this is a finding. 
 
Run the following to get a linked server login mapping: 
 
SELECT s.name, p.principal_id, l.remote_name 
FROM sys.servers s 
JOIN sys.linked_logins l ON s.server_id = l.server_id 
LEFT JOIN sys.server_principals p ON l.local_principal_id = p.principal_id 
WHERE s.is_linked = 1 
 
Review the linked login mapping and check the remote name as it can impersonate sysadmin.  If a login in the list is impersonating sysadmin and system documentation does not require this, it is a finding.'
  desc 'fix', "Disable use of or remove any linked servers that are not authorized.  
 
To remove a linked server and all associated logins run the following: 
 
sp_dropserver 'LinkedServerName', 'droplogins'; 
 
To remove a login from a linked server run the following: 
 
EXEC sp_droplinkedsrvlogin 'LoginName', NULL;"
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15177r313663_chk'
  tag severity: 'medium'
  tag gid: 'V-213960'
  tag rid: 'SV-213960r879587_rule'
  tag stig_id: 'SQL6-D0-007500'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-15175r313664_fix'
  tag 'documentable'
  tag legacy: ['SV-93889', 'V-79183']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
