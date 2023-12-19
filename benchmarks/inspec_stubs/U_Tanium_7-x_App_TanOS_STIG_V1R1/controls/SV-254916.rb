control 'SV-254916' do
  title 'The Tanium application must uniquely identify and authenticate nonorganizational users (or processes acting on behalf of nonorganizational users).'
  desc 'Lack of authentication and identification enables nonorganizational users to gain access to the application or possibly other information systems and provides an opportunity for intruders to compromise resources within the application or information system. 

Nonorganizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors and guest researchers). 

Nonorganizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server.'
  desc 'check', 'Local users can be identified by the following:

1. Using a web browser on a system, which has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner. 

3. Under "Permissions," select "Users".

4. Compare users listed to the prepared documentation. 

If documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups does not exist this is a finding.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium console users and their respective User Groups, Roles, Computer Groups, and associated LDAP security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58529r867646_chk'
  tag severity: 'medium'
  tag gid: 'V-254916'
  tag rid: 'SV-254916r867648_rule'
  tag stig_id: 'TANS-AP-000505'
  tag gtitle: 'SRG-APP-000180'
  tag fix_id: 'F-58473r867647_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
