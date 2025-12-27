control 'SV-213847' do
  title 'Unused database components that are integrated in SQL Server and cannot be uninstalled must be disabled.'
  desc 'SQL Server is capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software demonstrations, or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Unused and unnecessary SQL Server components increase the number of available attack vectors to SQL Server by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled.'
  desc 'check', 'Review the components and features included in SQL Server and capable of being disabled (by configuration settings, permissions and privileges, etc.).  Take note of those which are enabled.

Review the system documentation to verify that the enabled components or features are documented and authorized.  If any enabled components or features are not authorized, this is a finding.'
  desc 'fix', 'If any components or features of SQL Server are required for operation of applications that will be accessing SQL Server data or configuration, include them in the system documentation.

If any unused components or features of SQL Server are installed and cannot be uninstalled or removed, then disable those components or features.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15066r312892_chk'
  tag severity: 'medium'
  tag gid: 'V-213847'
  tag rid: 'SV-213847r395853_rule'
  tag stig_id: 'SQL4-00-017000'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-15064r312893_fix'
  tag 'documentable'
  tag legacy: ['SV-82341', 'V-67851']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
