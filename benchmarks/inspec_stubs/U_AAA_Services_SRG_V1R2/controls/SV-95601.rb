control 'SV-95601' do
  title 'AAA Services must be configured to uniquely identify and authenticate organizational users.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following.

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Verify AAA Services are configured to uniquely identify and authenticate organizational users. For STIGs produced from this requirement, when AAA Services are used to authenticate processes acting on behalf of organizational users, they also must be uniquely identified and authenticated.

If AAA Services are not configured to uniquely identify and authenticate organizational users, this is a finding.'
  desc 'fix', 'Configure AAA Services to uniquely identify and authenticate organizational users.'
  impact 0.7
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80629r1_chk'
  tag severity: 'high'
  tag gid: 'V-80891'
  tag rid: 'SV-95601r1_rule'
  tag stig_id: 'SRG-APP-000148-AAA-000390'
  tag gtitle: 'SRG-APP-000148-AAA-000390'
  tag fix_id: 'F-87747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
