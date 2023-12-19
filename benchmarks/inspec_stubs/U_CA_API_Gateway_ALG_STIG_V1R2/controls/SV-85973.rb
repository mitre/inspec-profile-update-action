control 'SV-85973' do
  title 'The CA API Gateway providing user authentication intermediary services must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following:

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

The CA API Gateway must have an Identity Provider registered/enabled on the Gateway in accordance with organizational requirements and must ensure authentication mechanisms are included with all Registered Services on the Gateway through the use of "Access Control" Assertions added to Registered Services policies.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click each of the Registered Services that require authentication of organizational users. 

Check the Registered Services for the existence of an Authentication Mechanism using an Access Control Assertion such as "Authenticate Against Identity Provider". 

Also validate that a Credential Source is added from the Access Control Assertions, such as "Require HTTP Basic Credentials" or "Require WS - Security Username Token Profile Credentials".

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click each of the Registered Services that require authentication of organizational users that do not have the required "Access Control" Assertions.

Add the "Authenticate Against Identity Provider" as well as a Credential Source such as "Require HTTP Basic Credentials" or "Require WS - Security Username Token Profile Credentials" from the list of "Access Control" Assertions. 

Click "Save and Activate" to activate the updated policy for the Registered Services.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71349'
  tag rid: 'SV-85973r1_rule'
  tag stig_id: 'CAGW-GW-000300'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-77659r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
