control 'SV-253784' do
  title 'The Tanium application must separate user functionality (including user interface services) from information system management functionality.'
  desc 'Application management functionality includes functions necessary for administration and requires privileged user access. Allowing nonprivileged users to access application management functionality capabilities increases the risk that nonprivileged users may obtain elevated privileges. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, different TCP/UDP ports, virtualization techniques, combinations of these methods, or other methods as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. This may include isolating the administrative interface on a different security domain and with additional access controls.'
  desc 'check', %q(Consult with the Tanium system administrator to review the documented list of Tanium users. The users' User Groups, Roles, Computer Groups, and correlated LDAP security groups or Local Users must be documented.

Local users can be identified by the following:

1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Permissions", select "Users".

4. Compare users that do not have a Domain listed to the prepared documentation. 

If documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups does not exist, this is a finding.)
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57236r842378_chk'
  tag severity: 'medium'
  tag gid: 'V-253784'
  tag rid: 'SV-253784r842380_rule'
  tag stig_id: 'TANS-00-001120'
  tag gtitle: 'SRG-APP-000211'
  tag fix_id: 'F-57187r842379_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
