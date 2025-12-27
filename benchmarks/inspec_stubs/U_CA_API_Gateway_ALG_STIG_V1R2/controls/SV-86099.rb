control 'SV-86099' do
  title 'The CA API Gateway providing encryption intermediary services must implement NIST FIPS-validated cryptography for digital signatures.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).

The CA API Gateway meets NIST FIPS-validated cryptography for digital signatures by using the built-in "Sign XML Element" and "Sign Element" Assertions within Registered Services policies, along with registered keypairs configured in accordance with organizational requirements.'
  desc 'check', 'Open the CA API GW - Policy Manager. 

Double-click each of the Registered Services that has the "Sign XML Element” or “Sign Element” Assertions, or require NIST-FIPS-validated cryptography for digital signatures be enabled. Verify that the Signature Digest Algorithm is SHA-256 or above to meet organizational requirements.

Verify that an approved public-private keypair exists in Tasks >> Manage Private Keys. Right-click on the aforementioned Assertions; whenever used, chose "Select Private Key" and verify the appropriate private key is assigned to be used for the signature. Additionally verify that the "security.fips.enabled" Cluster Wide Property is enabled. 

If any of the above steps are not met, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click each of the Registered Services that requires NIST-FIPS-validated cryptography for digital signatures to be enabled.

Add the following Assertion(s) in accordance with organizational need: "Sign XML Element" and/or "Sign Element".

Verify that the Signature Digest Algorithm is set to SHA-256 or above to meet organizational requirements.

Verify/install an approved public-private keypair in Tasks >> Manage Private Keys. 

Also, right-click on the aforementioned Assertions, whenever used, chose "Select Private Key", and verify the appropriate private key is assigned to be used for the signature. 

If the "security.fips.enabled" Cluster-Wide Property is not enabled, select "Manage Cluster-Wide Properties" from the "Tasks" menu. Click "Add" and select "security.fips.enabled" from the "Key:" drop-down list. 

Set the value to "True" and click "OK".'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71475'
  tag rid: 'SV-86099r1_rule'
  tag stig_id: 'CAGW-GW-000890'
  tag gtitle: 'SRG-NET-000510-ALG-000040'
  tag fix_id: 'F-77795r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
