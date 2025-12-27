control 'SV-235933' do
  title 'Oracle WebLogic must automatically audit account creation.'
  desc 'Application servers require user accounts for server management purposes, and if the creation of new accounts is not logged, there is limited or no capability to track or alarm on account creation. This could result in the circumvention of the normal account creation process and introduce a persistent threat. Therefore, an audit trail that documents the creation of application user accounts must exist.

An application server could possibly provide the capability to utilize either a local or centralized user registry. A centralized, enterprise user registry such as AD or LDAP is more likely to already contain provisions for automated account management, whereas a localized user registry will rely upon either the underlying OS or built-in application server user management capabilities. Either way, application servers must create a log entry when accounts are created.'
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
  tag check_id: 'C-39152r628575_chk'
  tag severity: 'medium'
  tag gid: 'V-235933'
  tag rid: 'SV-235933r628577_rule'
  tag stig_id: 'WBLC-01-000018'
  tag gtitle: 'SRG-APP-000509-AS-000234'
  tag fix_id: 'F-39115r628576_fix'
  tag 'documentable'
  tag legacy: ['SV-70469', 'V-56215']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
