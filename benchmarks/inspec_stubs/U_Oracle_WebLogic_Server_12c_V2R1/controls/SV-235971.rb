control 'SV-235971' do
  title 'Oracle WebLogic must encrypt passwords during transmission.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 

Application servers have the capability to utilize either certificates (tokens) or user IDs and passwords in order to authenticate. When the application server transmits or receives passwords, the passwords must be encrypted.'
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
8. Set all provider-specific values to configure the new authentication provider. Click 'Save'
9. Continuing from step 4, if the new authentication provider is perimeter-based, click 'New'. Enter a value in 'Name' field and select a valid authentication provider type (e.g., SAML2IdentityAsserter) in the 'Type' dropdown. Click 'OK'
10. From the list, select the newly created authentication identity asserter and select the 'Configuration' tab -> 'Provider Specific' tab
11. Set all provider-specific values to configure the new authentication identity asserter. Click 'Save'"
  impact 0.7
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39190r628689_chk'
  tag severity: 'high'
  tag gid: 'V-235971'
  tag rid: 'SV-235971r628691_rule'
  tag stig_id: 'WBLC-05-000168'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-39153r628690_fix'
  tag 'documentable'
  tag legacy: ['SV-70545', 'V-56291']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
