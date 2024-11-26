control 'SV-253782' do
  title 'The Tanium application must be configured for LDAP user/group synchronization to map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', "Consult with the Tanium system administrator to review the documented list of Tanium users. The users' User Groups, Roles, Computer Groups, and correlated LDAP security groups must be documented.

If the documentation does not exist or is missing any Tanium users and their respective User Groups, Roles, Computer Groups, and correlated LDAP security groups, this is a finding."
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 
 
2. Click "Administration" on the top navigation banner.
 
3. Under "Permissions", select "Users".

4. Prepare and maintain documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57234r842372_chk'
  tag severity: 'medium'
  tag gid: 'V-253782'
  tag rid: 'SV-253782r842374_rule'
  tag stig_id: 'TANS-00-001065'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-57185r842373_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
