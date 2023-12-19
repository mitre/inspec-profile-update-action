control 'SV-86063' do
  title 'The CA API Gateway providing user authentication intermediary services must conform to Federal Identity, Credential, and Access Management (FICAM) issued profiles.'
  desc 'Without conforming to FICAM-issued profiles, the information system may not be interoperable with FICAM authentication protocols, such as SAML 2.0 and OpenID 2.0.

Use of FICAM-issued profiles addresses open identity management standards.

This requirement only applies to components where this is specific to the function of the device or has the concept of a non-organizational user, (e.g., ALG capability that is the front end for an application in a DMZ).

CA API Gateway must be capable of producing and validating FICAM-compliant SAML.'
  desc 'check', 'Open the CA API GW - Policy Manager and double-click all Registered Services required to conform to FICAM-issued profiles. 

Verify the "Evaluate SAML Protocol Response" Assertion is included in the policy and set to evaluate only SAML 2.0 responses. 

Validate all additional parameters within the Assertion are set in accordance with organizational requirements for FICAM-issued profiles. 

If the "Evaluate SAML Protocol Response" Assertion is not included in the policy and set to evaluate only SAML 2.0 responses, this is a finding.'
  desc 'fix', 'Open the CA API GW - Policy Manager and double-click all Registered Services required to conform to FICAM issued profiles. 

Add the "Evaluate SAML Protocol Response" Assertion to the policy and set the SAML Version to 2.0.

Set all other configuration parameters within the Assertion to meet organizational requirements for FICAM-issued profiles.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71439'
  tag rid: 'SV-86063r1_rule'
  tag stig_id: 'CAGW-GW-000650'
  tag gtitle: 'SRG-NET-000349-ALG-000106'
  tag fix_id: 'F-77757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002014']
  tag nist: ['IA-8 (4)']
end
