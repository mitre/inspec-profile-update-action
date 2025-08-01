control 'SV-85949' do
  title 'The CA API Gateway providing intermediary services for remote access communications traffic must use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

The CA API Gateway uses the RSA BSAFE Crypto-J Software Module, which is validated to FIPS 140-2 Overall Level 1 when operated in FIPS mode. FIPS mode is not enabled by default and must be enabled.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select "Manage Cluster-Wide Properties" from the "Tasks" menu. 

If the "security.fips.enabled" property is not listed or is set to false, this is a finding. 

Additionally, select Tasks >> Manage Listen Ports and double-click on each SSL listen port.

Verify that no SSL versions are selected, TLS 1.0 is not selected, and only TLS 1.1, 1.2, and above are selected.

Verify that each Enabled Cipher Suites with a checkmark is included in NIST SP 800-52 section 3.3.2 Cipher Suites (or Appendix C if applicable). 

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Select "Manage Cluster-Wide Properties" from the "Tasks" menu. 

Click "Add" and select "security.fips.enabled" from the Key: drop-down list. Set the value to "true" and click "OK". 

API Gateway version 8.3 and later will automatically deselect TLS 1.0. 

For version 8.2 and prior, select Tasks >> Manage Listen Ports, double-click on each SSL listen port, select the SSL/TLS settings, deselect TLS 1.0, and select TLS 1.1 and TLS 1.2.

Verify that each Enabled Cipher Suites with a checkmark is included in NIST SP 800-52 section 3.3.2 Cipher Suites (or Appendix C if applicable).'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71723r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71325'
  tag rid: 'SV-85949r2_rule'
  tag stig_id: 'CAGW-GW-000200'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-77633r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
