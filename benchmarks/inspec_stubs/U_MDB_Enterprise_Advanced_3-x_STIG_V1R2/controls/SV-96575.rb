control 'SV-96575' do
  title 'Unused database components that are integrated in MongoDB and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for MongoDB by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.

'
  desc 'check', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), review the following parameters:

net:
http:
enabled: true
JSONPEnabled: true
RESTInterfaceEnabled: true

If any of the <booleans> are "True" or "Enabled", this is a finding.'
  desc 'fix', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), ensure the following parameters either:

Does not exist in the file
OR
Are set to "false" as shown below:

http:
enabled: false
JSONPEnabled: false
RESTInterfaceEnabled: false'
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81653r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81861'
  tag rid: 'SV-96575r1_rule'
  tag stig_id: 'MD3X-00-000290'
  tag gtitle: 'SRG-APP-000141-DB-000092'
  tag fix_id: 'F-88711r1_fix'
  tag satisfies: ['SRG-APP-000141-DB-000092', 'SRG-APP-000142-DB-000094']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-000382']
  tag nist: ['CM-7 a', 'CM-7 b']
end
