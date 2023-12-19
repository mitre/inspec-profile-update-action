control 'SV-215718' do
  title 'The BIG-IP APM module must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users) when connecting to virtual servers.'
  desc "To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses except the following:

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.

This requirement applies to ALGs that provide user proxy services, including identification and authentication. This service must use the site's directory service (e.g., Active Directory). Directory services must not be installed onto the gateway."
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for granting access.

Verify the Access Profile is configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).

If the BIG-IP APM is not configured to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users), this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure an access policy in the BIG-IP APM module to uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16911r290400_chk'
  tag severity: 'medium'
  tag gid: 'V-215718'
  tag rid: 'SV-215718r557355_rule'
  tag stig_id: 'F5BI-AP-000073'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag fix_id: 'F-16909r290401_fix'
  tag 'documentable'
  tag legacy: ['SV-74457', 'V-60027']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
