control 'SV-204761' do
  title 'The application server must separate hosted application functionality from application server management functionality.'
  desc 'The application server consists of the management interface and hosted applications.  By separating the management interface from hosted applications, the user must authenticate as a privileged user to the management interface before being presented with management functionality.  This prevents non-privileged users from having visibility to functions not available to the user.  By limiting visibility, a compromised non-privileged account does not offer information to the attacker to functionality and information needed to further the attack on the application server.

Application server management functionality includes functions necessary to administer the application server and requires privileged access via one of the accounts assigned to a management role.  The hosted application and hosted application functionality consists of the assets needed for the application to function, such as the business logic, databases, user authentication, etc.

The separation of application server administration functionality from hosted application functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, network addresses, network ports, or combinations of these methods, as appropriate.'
  desc 'check', 'Review the application server documentation and configuration to verify that the application server separates admin functionality from hosted application functionality.

If the application server does not separate application server admin functionality from hosted application functionality, this is a finding.'
  desc 'fix', 'Configure the application server so that admin management functionality and hosted applications are separated.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4881r282930_chk'
  tag severity: 'medium'
  tag gid: 'V-204761'
  tag rid: 'SV-204761r508029_rule'
  tag stig_id: 'SRG-APP-000211-AS-000146'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-4881r282931_fix'
  tag 'documentable'
  tag legacy: ['SV-46663', 'V-35376']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
