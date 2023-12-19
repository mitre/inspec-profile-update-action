control 'SV-215788' do
  title 'The BIG-IP Core implementation must be able to conform to FICAM-issued profiles when providing authentication to virtual servers.'
  desc 'Without conforming to Federal Identity, Credential, and Access Management (FICAM)-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

Use of FICAM-issued profiles addresses open identity management standards.

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user, (e.g., ALG capability that is the front end for an application in a DMZ).'
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to conform to FICAM-issued profiles when providing authentication.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section that "Access Policy" has been set to conform to FICAM-issued profiles when providing authentication to pools/nodes.

If the BIG-IP Core is not configured to conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to conform to FICAM-issued profiles when providing authentication.

Apply APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to conform to FICAM-issued profiles when providing authentication to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16980r291177_chk'
  tag severity: 'medium'
  tag gid: 'V-215788'
  tag rid: 'SV-215788r831471_rule'
  tag stig_id: 'F5BI-LT-000211'
  tag gtitle: 'SRG-NET-000349-ALG-000106'
  tag fix_id: 'F-16978r291178_fix'
  tag 'documentable'
  tag legacy: ['V-60357', 'SV-74787']
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
