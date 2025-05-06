control 'SV-252156' do
  title 'Unused database components that are integrated in MongoDB and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for MongoDB by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.'
  desc 'check', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), review the following parameters:

net:
   http:
      enabled: true
      JSONPEnabled: true
      RESTInterfaceEnabled: true

If any of the booleans are true or enabled, this is a finding.'
  desc 'fix', 'In the MongoDB database configuration file (default location: /etc/mongod.conf), ensure the following parameters either:

Does not exist in the file
OR
Are set to false as shown below:

   http:
      enabled: false
      JSONPEnabled: false
      RESTInterfaceEnabled: false'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55612r813848_chk'
  tag severity: 'medium'
  tag gid: 'V-252156'
  tag rid: 'SV-252156r813850_rule'
  tag stig_id: 'MD4X-00-002600'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-55562r813849_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
