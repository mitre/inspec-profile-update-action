control 'SV-237032' do
  title 'The A10 Networks ADC, when used for TLS encryption and decryption, must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks which exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol thus are in scope for this requirement. NIS SP 800-52 provides guidance.

SP 800-52 sets TLS version 1.1 as a minimum version, thus all versions of SSL are not allowed (including for client negotiation) either on DoD-only or on public facing servers.'
  desc 'check', 'If the device does not provide intermediary services for TLS, or application protocols that use TLS (e.g., DNSSEC or HTTPS), this is not applicable. 

Review the device configuration.

View the configured cipher templates (if any):
show slb template cipher

The following cipher suites are in compliance:
TLS1_RSA_AES_128_SHA
TLS1_RSA_AES_128_SHA256
TLS1_RSA_AES_256_SHA
TLS1_RSA_AES_256_SHA256

If any of the configured cipher templates contain any cipher suites that are not in compliance, this is a finding.

View the configured SLB SSL templates:
show slb template server-ssl

If any of the configured SLB SSL templates list version 30, 31, 32, this is a finding.

If any of the configured SLB SSL templates contain any cipher suites that are not in compliance, this is a finding.'
  desc 'fix', 'The following command validates real servers based on their certificates:
slb template server-ssl [template-name]

The following sub-command specifies the version of SSL/TLS used:
version [30 | 31 | 32 |33]

Note: Options 30, 31, or 32 are not compliant; use option 33 or higher instead.

The following sub-command specifies the cipher suite to support for certificates from servers:
cipher [cipher suite]

The following cipher suites are in compliance:
TLS1_RSA_AES_128_SHA
TLS1_RSA_AES_128_SHA256
TLS1_RSA_AES_256_SHA
TLS1_RSA_AES_256_SHA256

Optionally, a cipher template containing these cipher suites can be configured and applied.

The following command creates a cipher template:
slb template cipher [template-name]

The following command binds the cipher template to the server-ssl template:
template cipher [template-name]'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40251r695312_chk'
  tag severity: 'medium'
  tag gid: 'V-237032'
  tag rid: 'SV-237032r639543_rule'
  tag stig_id: 'AADC-AG-000018'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-40214r695313_fix'
  tag 'documentable'
  tag legacy: ['V-67957', 'SV-82447']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
