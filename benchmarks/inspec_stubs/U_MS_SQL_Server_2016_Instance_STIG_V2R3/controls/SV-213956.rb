control 'SV-213956' do
  title 'Unused database components that are integrated in SQL Server and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).  
 
It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.  
 
DBMSs must adhere to the principles of least functionality by providing only essential capabilities. 
 
Unused, unnecessary DBMS components increase the attack vector for SQL Server by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.'
  desc 'check', 'From the server documentation, obtain a listing of required components. 

Generate a listing of components installed on the server.

Click Start >> Type "SQL Server 2016 Installation Center" >> Launch the program >> Click Tools >> Click "Installed SQL Server features discovery report"

Compare the feature listing against the required components listing. Note any components that are installed, but not required.

Launch SQL Server Configuration Manager. 

If any components that are installed but are not required are not disabled, this is a finding. 

If any required components are not installed, this is a finding.'
  desc 'fix', 'Disable any unused components or features that cannot be uninstalled.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15173r313651_chk'
  tag severity: 'medium'
  tag gid: 'V-213956'
  tag rid: 'SV-213956r617437_rule'
  tag stig_id: 'SQL6-D0-007100'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-15171r313652_fix'
  tag 'documentable'
  tag legacy: ['SV-93881', 'V-79175']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
