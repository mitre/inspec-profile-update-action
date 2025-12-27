control 'SV-80535' do
  title 'Trend Deep Security must reside on a Web Server configured for multifactor authentication.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', 'Review the Web Server hosting Trend Deep Security to ensure multifactor authentication has been configured.

1. Open Internet Information Services (IIS) Manager.
2. In the console tree, expand the server name.
3. In the server Home page, double-click Authentication to open the Authentication page.
4. In the  Authentication page, right-click AD Client Certificate Authentication, and ensure "Enable" is selected.
5. Close the Authentication page.
6. In the server Home page, double-click SSL Settings to open the SSL Settings page.
7. Ensure the "Require SSL" Checkbox is checked, and "Require" radio button is selected.
8. Close the SSL Settings page.
9. Close IIS Manager.

If "Enable" is not selected in the Authentication page, this is a finding.
If "Require SSL" is not selected in the SSL Settings page, this is a finding.
If "Ignore" or "Accept" radio buttons are selected in the SSL settings page, this is a finding.'
  desc 'fix', 'Configure the Web Server hosting Trend Deep Security for multifactor authentication.

To configure the authentication method in IIS:
1. Open Internet Information Services (IIS) Manager.
2. In the console tree, expand the server name.
3. In the server Home page, double-click Authentication to open the Authentication page.
4. In the  Authentication page, right-click AD Client Certificate Authentication, and click "Enable".
5. Close the Authentication page.
6. In the server Home page, double-click SSL Settings to open the SSL Settings page.
7. Select the "Require SSL" Checkbox, and "Require" radio button.
8. Close the SSL Settings page.
9. Close IIS Manager.'
  impact 0.7
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66689r1_chk'
  tag severity: 'high'
  tag gid: 'V-66045'
  tag rid: 'SV-80535r1_rule'
  tag stig_id: 'TMDS-00-004520'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-72121r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
