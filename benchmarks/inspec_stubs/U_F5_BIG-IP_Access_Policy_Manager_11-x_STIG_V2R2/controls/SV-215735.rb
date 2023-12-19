control 'SV-215735' do
  title 'The BIG-IP APM module must conform to FICAM-issued profiles.'
  desc 'Without conforming to Federal Identity, Credential, and Access Management (FICAM)-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

Use of FICAM-issued profiles addresses open identity management standards.

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user, (e.g., ALG capability that is the front end for an application in a DMZ).'
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services to non-organizational users, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used to identify and authenticate non-organizational users.

Verify the Access Profile is configured to conform to FICAM-issued profiles.

If the BIG-IP APM module is not configured to conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'If the BIG-IP APM module provides user authentication intermediary services to non-organizational users, configure a profile in the BIG-IP APM module that conforms to FICAM-issued profiles.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16928r290451_chk'
  tag severity: 'medium'
  tag gid: 'V-215735'
  tag rid: 'SV-215735r831445_rule'
  tag stig_id: 'F5BI-AP-000211'
  tag gtitle: 'SRG-NET-000349-ALG-000106'
  tag fix_id: 'F-16926r290452_fix'
  tag 'documentable'
  tag legacy: ['V-60061', 'SV-74491']
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
