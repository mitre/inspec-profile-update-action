control 'SV-86097' do
  title 'The CA API Gateway providing encryption intermediary services must implement NIST FIPS-validated cryptography to generate cryptographic hashes.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).

The CA API Gateway uses the RSA BSAFE Crypto-J Software Module for cryptographic hashing, which is validated to FIPS 140-2 overall Level 1 when operated in FIPS mode. FIPS mode is not enabled by default and must be enabled on the CA API Gateway. Hashing algorithms used in signature operations are configured as per the assertion in the policy.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select "Manage Cluster-Wide Properties" from the "Tasks" menu. 

If the "security.fips.enabled" property is not listed or set to "True", this is a finding. 

Additionally, select Tasks >> Manage Listen Ports and double-click on each SSL listen port. Verify that no SSL versions are selected, TLS 1.0 is not selected, and only TLS 1.1, 1.2, and above are selected.

Verify that each Enabled Cipher Suites with a checkmark is included in NIST SP 800-52 section 3.3.2 Cipher Suites (or Appendix C if applicable).

When using the following Assertions in the policy, verify only the approved secure hashes are selected: "Sign XML Element", "Sign Element", "Generate Security Hash".

Verify that SHA-1 and below are not selected wherever appropriate. 

If not, this is also a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Select "Manage Cluster-Wide Properties" from the "Tasks" menu. 

Click "Add" and select "security.fips.enabled" from the "Key:" drop-down list. 

Set the value to "True" and click "OK". 

API Gateway version 8.3 and later will automatically deselect TLS 1.0. For version 8.2 and prior, select Tasks >> Manage Listen Ports, double-click on each SSL listen port, select the SSL/TLS settings, deselect TLS 1.0, and select TLS 1.1 and TLS 1.2.

Verify that each Enabled Cipher Suites with a checkmark is included in NIST SP 800-52 section 3.3.2 Cipher Suites (or Appendix C if applicable). 

Within each Registered Service using the following Assertions in the policy, enable only the approved secure hashes are selected: "Sign XML Element", "Sign Element", "Generate Security Hash".

Also verify SHA-1 and below are not selected wherever appropriate.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71473'
  tag rid: 'SV-86097r1_rule'
  tag stig_id: 'CAGW-GW-000880'
  tag gtitle: 'SRG-NET-000510-ALG-000025'
  tag fix_id: 'F-77793r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
