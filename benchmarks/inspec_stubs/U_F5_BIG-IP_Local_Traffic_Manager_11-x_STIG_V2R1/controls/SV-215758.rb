control 'SV-215758' do
  title 'The BIG-IP Core implementation must be configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users) when connecting to virtual servers.'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.
Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following:

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication.

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway."
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify the BIG-IP Core is configured with an APM policy to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an APM access policy to uniquely identify and authenticate organizational users when connecting to virtual servers.

If the BIG-IP Core does not uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

Apply the APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users) when connecting to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16950r291087_chk'
  tag severity: 'medium'
  tag gid: 'V-215758'
  tag rid: 'SV-215758r557356_rule'
  tag stig_id: 'F5BI-LT-000073'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-16948r291088_fix'
  tag 'documentable'
  tag legacy: ['V-60297', 'SV-74727']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
