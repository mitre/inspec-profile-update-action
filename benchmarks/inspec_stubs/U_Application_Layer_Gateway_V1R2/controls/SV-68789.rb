control 'SV-68789' do
  title 'The ALG providing user authentication intermediary services must conform to FICAM-issued profiles.'
  desc 'Without conforming to Federal Identity, Credential, and Access Management (FICAM)-issued profiles, the information system may not be interoperable with FICAM-authentication protocols, such as SAML 2.0 and OpenID 2.0.

Use of FICAM-issued profiles addresses open identity management standards.

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user, (e.g., ALG capability that is the front end for an application in a DMZ).'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG conform to FICAM-issued profiles.

If the ALG does not conform to FICAM-issued profiles, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure ALG to conform to FICAM-issued profiles.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54543'
  tag rid: 'SV-68789r1_rule'
  tag stig_id: 'SRG-NET-000349-ALG-000106'
  tag gtitle: 'SRG-NET-000349-ALG-000106'
  tag fix_id: 'F-59397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
