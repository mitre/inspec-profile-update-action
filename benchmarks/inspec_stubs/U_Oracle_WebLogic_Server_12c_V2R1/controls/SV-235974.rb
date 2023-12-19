control 'SV-235974' do
  title 'Oracle WebLogic must map the PKI-based authentication identity to the user account.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information. 

Application servers must provide the capability to utilize and meet requirements of the DoD Enterprise PKI infrastructure for application authentication.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Security Realms'
3. Select realm to configure (default is 'myrealm')
4. Select 'Providers' tab -> 'Authentication' tab
5. Ensure the list of 'Authentication Providers' contains at least one non-Default Authentication Provider
6. If the Authentication Provider is perimeter-based, ensure the list contains at least one non-Default IdentityAsserter

If PKI-based authentication is being used and the list of 'Authentication Providers' does not contain at least one non-Default Authentication Provider, this is a finding. 

If PKI-based authentication is being used and the Authentication Provider is perimeter-based and the list of 'Authentication Providers' does not contain at least one non-Default IdentityAsserter, this is a finding."
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
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39193r628698_chk'
  tag severity: 'medium'
  tag gid: 'V-235974'
  tag rid: 'SV-235974r628700_rule'
  tag stig_id: 'WBLC-05-000174'
  tag gtitle: 'SRG-APP-000177-AS-000126'
  tag fix_id: 'F-39156r628699_fix'
  tag 'documentable'
  tag legacy: ['SV-70551', 'V-56297']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
