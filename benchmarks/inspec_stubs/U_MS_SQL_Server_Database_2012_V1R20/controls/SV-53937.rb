control 'SV-53937' do
  title 'Unused database components and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software demonstrations or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, yet cannot be disabled.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Unused and unnecessary SQL Server components increase the number of available attack vectors to SQL Server by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.'
  desc 'check', 'Review the list of components or optional features installed with SQL Server.
If optional features or components are NOT installed, this is not a finding.

If unused components or features of SQL Server are installed, then review the system documentation to verify unused components or features are documented and authorized.

If any are not documented and authorized, this is a finding.'
  desc 'fix', 'If any database components or objects of SQL Server are required for operation of applications that will be accessing SQL Server data or configuration, include them in the system documentation. If any unused components or objects of SQL Server are installed, uninstall or remove unused components or objects.'
  impact 0.5
  ref 'DPMS Target SQL Server Database 2012'
  tag check_id: 'C-47946r3_chk'
  tag severity: 'medium'
  tag gid: 'V-41409'
  tag rid: 'SV-53937r3_rule'
  tag stig_id: 'SQL2-00-016900'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-46837r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
