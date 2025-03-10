control 'SV-222430' do
  title 'The application must execute without excessive account permissions.'
  desc 'Applications are often designed to utilize a user account.  The account represents a means to control application permissions and access to OS resources, application resources or both.  

When the application is designed and installed, care must be taken not to assign excessive permissions to the user account that is used by the application.  

An application operating with unnecessary privileges can potentially give an attacker access to the underlying operating system or if the privileges required for application execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Applications must be designed and configured to operate with only those permissions that are required for proper operation.'
  desc 'check', 'Review the system documentation or interview the application representative and identify if the application utilizes an account in order to operate.

Determine the OS user groups in which each application account is a member.  List the user rights assigned to these users and groups using relevant OS commands and evaluate whether any of them provide admin rights or if they are unnecessary or excessive. 

If the application connects to a database, open an admin console to the database and view the database users, their roles and group rights.

Locate the application user account used to access the database and examine the accounts privileges. This includes group privileges.

If the application user account has excessive OS privileges such as being in the admin group, database privileges such as being in the DBA role, has the ability to create, drop, alter the database (not application database tables), or if the application user account has other excessive or undefined system privileges, this is a finding.'
  desc 'fix', 'Configure the application accounts with minimalist privileges. Do not allow the application to operate with admin credentials.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24100r493198_chk'
  tag severity: 'high'
  tag gid: 'V-222430'
  tag rid: 'SV-222430r508029_rule'
  tag stig_id: 'APSC-DV-000510'
  tag gtitle: 'SRG-APP-000342'
  tag fix_id: 'F-24089r493199_fix'
  tag 'documentable'
  tag legacy: ['SV-83961', 'V-69339']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
