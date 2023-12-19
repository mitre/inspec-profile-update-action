control 'SV-80399' do
  title 'Trend Deep Security must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', "Review the Trend Deep Security server configuration to ensure organizational users (or processes acting on behalf of organizational users) are uniquely identified and authenticated.

Verify the user accounts under Administration >> User Management >> Users

If the accounts configured do not uniquely specify the organizational user's affiliation, this is a finding."
  desc 'fix', 'Configure the Trend Deep Security server to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Configure the appropriate affiliation display for the specified user under Administration >> User Management >> Users
Right click the user account.
Click "Properties" and Select “User Name”. 
Enter the appropriate user identifiers.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66557r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65909'
  tag rid: 'SV-80399r1_rule'
  tag stig_id: 'TMDS-00-000135'
  tag gtitle: 'SRG-APP-000148'
  tag fix_id: 'F-71985r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
