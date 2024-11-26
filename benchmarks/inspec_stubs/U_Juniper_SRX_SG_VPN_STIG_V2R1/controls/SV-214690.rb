control 'SV-214690' do
  title 'The Juniper SRX Services Gateway VPN Internet Key Exchange (IKE) must use cryptography that is compliant with Suite B parameters when transporting classified traffic across an unclassified network.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RFC 6379 Suite B Cryptographic Suites for IPsec defines four cryptographic user interface suites for deploying IPsec. Each suite provides choices for Encapsulating Security Payload (ESP) and IKE. The four suites are differentiated by the choice of IKE authentication and key exchange, cryptographic algorithm strengths, and whether ESP is to provide both confidentiality and integrity or integrity only. The suite names are based on the Advanced Encryption Standard (AES) mode and AES key length specified for ESP. Two suites are defined for transporting classified information up to SECRET level—one for both confidentiality and integrity and one for integrity only. There are also two suites defined for transporting classified information up to TOP SECRET level.'
  desc 'check', 'Ask the site representative which proposal implements Suite B.

[edit]
show security ike <suiteb-proposal-name>

View the configured options.

If the value of the authentication-method and other options are not set for Suite B compliance, this is a finding.'
  desc 'fix', 'The following example commands configure the IKE (phase 1) Suite B proposal. Note that SRX must have Junos 12.1X46 or later to support SuiteB. 

[edit]
set security ike proposal suiteb-proposal
set ike proposal suiteb-proposal authentication-method ecdsa-signatures-384
set ike proposal suiteb-proposal dh-group group20
set ike proposal suiteb-proposal authentication-algorithm sha-384
set ike proposal suiteb-proposal encryption-algorithm aes-256-cbc'
  impact 0.7
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15891r297657_chk'
  tag severity: 'high'
  tag gid: 'V-214690'
  tag rid: 'SV-214690r383485_rule'
  tag stig_id: 'JUSX-VN-000023'
  tag gtitle: 'SRG-NET-000352'
  tag fix_id: 'F-15889r297658_fix'
  tag 'documentable'
  tag legacy: ['V-66625', 'SV-81115']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
