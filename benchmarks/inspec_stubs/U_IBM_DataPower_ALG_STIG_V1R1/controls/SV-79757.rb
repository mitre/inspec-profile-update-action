control 'SV-79757' do
  title 'The DataPower Gateway providing user authentication intermediary services must conform to FICAM-issued profiles.'
  desc 'Without conforming to Federal Identity, Credential, and Access Management (FICAM)-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

Use of FICAM-issued profiles addresses open identity management standards.

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user, (e.g., ALG capability that is the front end for an application in a DMZ).'
  desc 'check', 'Search Bar "AAA Policy" >> Select AAA Policy >> Identity Extraction "Name from SAML Authentication assertion" >> Authentication >> Method "Accept SAML assertion with valid signature".

If no AAA Policy is present, this is a finding.'
  desc 'fix', 'Search Bar “AAA Policy” >> Select AAA Policy >> Identity Extraction “Name from SAML Authentication assertion” >> Authentication >> Method “Accept SAML assertion with valid signature”'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65895r3_chk'
  tag severity: 'medium'
  tag gid: 'V-65267'
  tag rid: 'SV-79757r1_rule'
  tag stig_id: 'WSDP-AG-000097'
  tag gtitle: 'SRG-NET-000349-ALG-000106'
  tag fix_id: 'F-71207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
