control 'SV-204741' do
  title 'The application server must limit privileges to change the software resident within software libraries.'
  desc 'Application servers have the ability to specify that the hosted applications utilize shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that non-privileged users cannot modify any shared library code at all.'
  desc 'check', 'Check the application server documentation and configuration to determine if the application server provides role-based access that limits the capability to change shared software libraries.

Validate file permission settings to ensure library files are secured in relation to OS access.

If the application server does not meet this requirement, this is a finding.'
  desc 'fix', 'Configure the application server to limit privileges to change the software resident within software libraries through the use of defined user roles and file permissions.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4861r282870_chk'
  tag severity: 'medium'
  tag gid: 'V-204741'
  tag rid: 'SV-204741r879586_rule'
  tag stig_id: 'SRG-APP-000133-AS-000092'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-4861r282871_fix'
  tag 'documentable'
  tag legacy: ['SV-46511', 'V-35224']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
