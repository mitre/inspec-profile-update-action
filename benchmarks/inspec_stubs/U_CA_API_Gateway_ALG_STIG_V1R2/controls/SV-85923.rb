control 'SV-85923' do
  title 'The CA API Gateway providing intermediary services for remote access communications traffic must use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

The CA API Gateway uses the RSA BSAFE Crypto-J Software Module for cryptography, which is validated to FIPS 140-2 Overall Level 1 when operated in FIPS mode. FIPS mode is not enabled by default and must be enabled to meet this requirement.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Select Tasks >> Manage Listen Ports and double-click on each SSL listen port.

Verify that no SSL versions are selected, TLS 1.0 is not selected, and only TLS 1.1, 1.2, and above are selected. 

Verify that each Enabled Cipher Suites with a checkmark is included in NIST SP 800-52 section 3.3.2 Cipher Suites (or Appendix C if applicable). 

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Select Tasks >> Manage Listen Ports, double-click on each SSL listen port, select the SSL/TLS settings, deselect TLS 1.0, and select TLS 1.1 and TLS 1.2.

Verify that each Enabled Cipher Suites with a checkmark is included in NIST SP 800-52 section 3.3.2 Cipher Suites (or Appendix C if applicable).'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71299'
  tag rid: 'SV-85923r1_rule'
  tag stig_id: 'CAGW-GW-000170'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-77611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
