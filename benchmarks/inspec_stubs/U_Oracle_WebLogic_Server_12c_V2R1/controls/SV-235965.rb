control 'SV-235965' do
  title 'Oracle WebLogic must authenticate users individually prior to using a group authenticator.'
  desc 'To assure individual accountability and prevent unauthorized access, application server users (and any processes acting on behalf of application server users) must be individually identified and authenticated. 

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. 

Application servers must ensure that individual users are authenticated prior to authenticating via role or group authentication. This is to ensure that there is non-repudiation for actions taken.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Ensure the list of 'Authentication Providers' contains at least one non-Default Authentication Provider
6. If the Authentication Provider is perimeter-based, ensure the list contains at least one non-Default IdentityAsserter

If the list of 'Authentication Providers' does not contain at least one non-Default Authentication Provider, this is a finding. 

If the Authentication Provider is perimeter-based and the list of 'Authentication Providers' does not contain at least one non-Default IdentityAsserter, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Utilize 'Change Center' to create a new change session
6. Click 'New'. Enter a value in 'Name' field and select a valid authentication provider type (e.g., LDAPAuthenticator) in the 'Type' dropdown. Click 'OK'
7. From the list, select the newly created authentication provider and select the 'Configuration' tab -> 'Provider Specific' tab
8. Set all provider specific values to configure the new authentication provider. Click 'Save'
9. Continuing from step 4, if the new authentication provider is perimeter-based, click 'New'. Enter a value in 'Name' field and select a valid authentication provider type (e.g., SAML2IdentityAsserter) in the 'Type' dropdown. Click 'OK'
10. From the list, select the newly created authentication identity asserter and select the 'Configuration' tab -> 'Provider Specific' tab
11. Set all provider specific values to configure the new authentication identity asserter. Click 'Save'"
  impact 0.7
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39184r628671_chk'
  tag severity: 'high'
  tag gid: 'V-235965'
  tag rid: 'SV-235965r628673_rule'
  tag stig_id: 'WBLC-05-000153'
  tag gtitle: 'SRG-APP-000153-AS-000104'
  tag fix_id: 'F-39147r628672_fix'
  tag 'documentable'
  tag legacy: ['SV-70533', 'V-56279']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
