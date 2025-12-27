control 'SV-213954' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plugins not related to requirements or providing a wide array of functionality, not required for every mission, that cannot be disabled. 
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities. 
 
Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to SQL Server and host system.'
  desc 'check', 'Review the server documentation, if this system is identified as a development or test system, this check is Not Applicable. 
 
If this system is identified as production, gather a listing of databases from the server and look for any matching the following general demonstration database names: 
 
pubs 
Northwind
AdventureWorks 
WorldwideImporters 
 
If any of these databases exist, this is a finding.'
  desc 'fix', 'Remove all demonstration or sample databases from production instances.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15171r313645_chk'
  tag severity: 'medium'
  tag gid: 'V-213954'
  tag rid: 'SV-213954r879587_rule'
  tag stig_id: 'SQL6-D0-006900'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-15169r313646_fix'
  tag 'documentable'
  tag legacy: ['SV-93877', 'V-79171']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
