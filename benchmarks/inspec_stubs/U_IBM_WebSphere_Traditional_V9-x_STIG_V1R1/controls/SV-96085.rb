control 'SV-96085' do
  title 'The WebSphere Application Servers must not be in the DMZ.'
  desc 'The application server consists of the management interface and hosted applications. By separating the management interface from hosted applications, the user must authenticate as a privileged user to the management interface before being presented with management functionality. This prevents non-privileged users from having visibility to functions not available to the user. By limiting visibility, a compromised non-privileged account does not offer information to the attacker to functionality and information needed to further the attack on the application server.

Application server management functionality includes functions necessary to administer the application server and requires privileged access via one of the accounts assigned to a management role. The hosted application and hosted application functionality consists of the assets needed for the application to function, such as the business logic, databases, user authentication, etc.

The separation of application server administration functionality from hosted application functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, network addresses, network ports, or combinations of these methods, as appropriate.'
  desc 'check', %q(Review System Security Plan and system architecture documentation.

Interview the system administrator.

Identify any DMZ networks.

If there are no DMZ networks in the application server's architecture, this requirement is NA.

In the administrative console, click Servers >> Server Types >> WebSphere application servers.

For each application server, review the "hostname" field and determine if the application server has a DMZ network IP address. 

If any application server is hosted in the DMZ network, this is a finding.)
  desc 'fix', 'If any application server host is installed in the DMZ, reassign IP address to a secured network and reconfigure the application server.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81081r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81371'
  tag rid: 'SV-96085r1_rule'
  tag stig_id: 'WBSP-AS-001390'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag fix_id: 'F-88157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
