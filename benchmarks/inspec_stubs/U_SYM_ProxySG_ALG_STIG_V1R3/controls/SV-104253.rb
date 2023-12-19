control 'SV-104253' do
  title 'Symantec ProxySG providing user authentication intermediary services must conform to Federal Identity, Credential, and Access Management (FICAM)-issued profiles.'
  desc 'Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

Use of FICAM-issued profiles addresses open identity management standards.

This only applies to components where this is specific to the function of the device or has the concept of a nonorganizational user (e.g., ALG capability that is the front end for an application in a DMZ).'
  desc 'check', 'Configure ProxySG to conform to a FICAM-authentication protocol and verify that SAML authentication has been configured.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Click "SAML" and verify that each tab has been configured properly per the organizational requirement.

If Symantec ProxySG providing user authentication intermediary services does not conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'Configure ProxySG to conform to a FICAM-authentication protocol and configure it to use SAML authentication.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. Click "SAML" and configure.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93485r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94299'
  tag rid: 'SV-104253r1_rule'
  tag stig_id: 'SYMP-AG-000430'
  tag gtitle: 'SRG-NET-000349-ALG-000106'
  tag fix_id: 'F-100415r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
