control 'SV-213850' do
  title 'SQL Server must be configured to prohibit or restrict the use of unauthorized network protocols.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Additionally, it is sometimes convenient to provide multiple services from a single component of an information system (e.g., email and web services) but doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Database Management Systems using ports, protocols, and services deemed unsafe are open to attack through those ports, protocols, and services. This can allow unauthorized access to the database and, through the database, to other components of the information system.

For information on approved and prohibited ports, protocols, and services, see the Ports, Protocols, and Services Management (PPSM) section of DoD Cyber Exchange web site: https://public.cyber.mil/connect/ppsm/.

"Functions" in this requirement refers to system and infrastructure functionality, not to functions in mathematics and programming languages.'
  desc 'check', 'Open SQL Server Configuration Manager. Navigate to SQL Server Network Configuration >  Protocols for <instance name>, where <instance name> is a placeholder for the SQL Server instance name.

If any listed protocol is enabled but not authorized, this is a finding.'
  desc 'fix', 'In SQL Server Configuration Manager, right-click on each listed protocol that is enabled but not authorized; select Disable.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2014 Instance'
  tag check_id: 'C-15069r312901_chk'
  tag severity: 'medium'
  tag gid: 'V-213850'
  tag rid: 'SV-213850r744320_rule'
  tag stig_id: 'SQL4-00-017400'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-15067r312902_fix'
  tag 'documentable'
  tag legacy: ['SV-82349', 'V-67859']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
