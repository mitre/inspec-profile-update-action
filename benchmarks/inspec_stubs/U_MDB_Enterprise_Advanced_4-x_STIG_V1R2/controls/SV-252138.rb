control 'SV-252138' do
  title 'Unused database components that are integrated in MongoDB and cannot be uninstalled must be disabled.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives.

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.

Unused, unnecessary DBMS components increase the attack vector for MongoDB by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced. Components of the system that are unused and cannot be uninstalled must be disabled. The techniques available for disabling components will vary by DBMS product, OS, and the nature of the component and may include DBMS configuration settings, OS service settings, OS file access security, and DBMS user/role permissions.'
  desc 'check', 'Inspect the MongoDB database configuration file (default location: /etc/mongod.conf) for any net.http options similar in construct to the following:

net:
   http:
      option 1: value
      option 2: value

Example:

It may appear similar to the following (having one or more options):

net:
   http:
      enabled: true
      port: port number
      JSONPEnabled: true
      RESTInterfaceEnabled: true

If the configuration file contains any "http:" options under "net:", this is a finding.'
  desc 'fix', 'MongoDB 3.6 removed the following deprecated HTTP interface and REST API to MongoDB and should not be used.

net.http.enabled
net.http.JSONPEnabled
net.http.port
net.http.RESTInterfaceEnabled

In the MongoDB database configuration file (default location: /etc/mongod.conf), remove all http: options underneath net: from the configuration file.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55594r816977_chk'
  tag severity: 'medium'
  tag gid: 'V-252138'
  tag rid: 'SV-252138r816978_rule'
  tag stig_id: 'MD4X-00-000500'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-55544r813795_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
