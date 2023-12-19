control 'SV-235964' do
  title 'Oracle WebLogic must uniquely identify and authenticate users (or processes acting on behalf of users).'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. 

The application server must uniquely identify and authenticate application server users or processes acting on behalf of users. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.'
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
11. Set all provider-specific values to configure the new authentication identity asserter. Click 'Save'"
  impact 0.7
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39183r628668_chk'
  tag severity: 'high'
  tag gid: 'V-235964'
  tag rid: 'SV-235964r628670_rule'
  tag stig_id: 'WBLC-05-000150'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-39146r628669_fix'
  tag 'documentable'
  tag legacy: ['SV-70531', 'V-56277']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
