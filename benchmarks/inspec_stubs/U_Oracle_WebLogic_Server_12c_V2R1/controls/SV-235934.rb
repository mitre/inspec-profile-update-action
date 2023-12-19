control 'SV-235934' do
  title 'Oracle WebLogic must automatically audit account modification.'
  desc 'Once an attacker establishes initial access to a system, they often attempt to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account.

Application servers have the capability to contain user information in a local user store, or they can leverage a centralized authentication mechanism like LDAP. Either way, the mechanism used by the application server must automatically log when user accounts are modified.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Auditing' tab
5. Ensure the list of 'Auditing Providers' contains at least one Auditing Provider
6. From 'Domain Structure', select the top-level domain link
7. Click 'Advanced' near the bottom of the page
8. Ensure 'Configuration Audit Type' is set to 'Change Log and Audit'

If the 'Configuration Audit Type' is not set to 'Change Log and Audit', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Auditing' tab
5. Utilize 'Change Center' to create a new change session
6. Click 'New'. Enter a value in 'Name' field and select an auditing provider type (ex: DefaultAuditor) in the 'Type' dropdown. Click 'OK'.
7. From 'Domain Structure', select the top-level domain link
8. Click 'Advanced' near the bottom of the page
9. Set 'Configuration Audit Type' dropdown to 'Change Log and Audit'
10. Click 'Save', and from 'Change Center' click 'Activate Changes' to enable configuration changes"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39153r628578_chk'
  tag severity: 'medium'
  tag gid: 'V-235934'
  tag rid: 'SV-235934r628580_rule'
  tag stig_id: 'WBLC-01-000019'
  tag gtitle: 'SRG-APP-000509-AS-000234'
  tag fix_id: 'F-39116r628579_fix'
  tag 'documentable'
  tag legacy: ['SV-70471', 'V-56217']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
