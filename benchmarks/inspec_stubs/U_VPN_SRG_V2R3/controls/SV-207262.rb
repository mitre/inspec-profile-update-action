control 'SV-207262' do
  title 'The IPsec VPN Gateway Internet Key Exchange (IKE) must use cryptography that is compliant with Suite B parameters when transporting classified traffic across an unclassified network.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VPN gateway must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

RFC 6379 Suite B Cryptographic Suites for IPsec defines four cryptographic user interface suites for deploying IPsec. Each suite provides choices for Encapsulating Security Payload (ESP) and IKE. The four suites are differentiated by the choice of IKE authentication and key exchange, cryptographic algorithm strengths, and whether ESP is to provide both confidentiality and integrity or integrity only. The suite names are based on the Advanced Encryption Standard (AES) mode and AES key length specified for ESP. Two suites are defined for transporting classified information up to SECRET level—one for both confidentiality and integrity and one for integrity only. There are also two suites defined for transporting classified information up to TOP SECRET level.'
  desc 'check', 'Verify the IPsec VPN Gateway Internet Key Exchange (IKE) uses cryptography that is compliant with Suite B parameters when transporting classified traffic across an unclassified network.

If the IPsec VPN Gateway Internet Key Exchange (IKE) does not use cryptography that is compliant with Suite B parameters when transporting classified traffic across an unclassified network, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway Internet Key Exchange (IKE) to use cryptography that is compliant with Suite B parameters when transporting classified traffic across an unclassified network.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7522r378407_chk'
  tag severity: 'high'
  tag gid: 'V-207262'
  tag rid: 'SV-207262r608988_rule'
  tag stig_id: 'SRG-NET-000565-VPN-002400'
  tag gtitle: 'SRG-NET-000565'
  tag fix_id: 'F-7522r378408_fix'
  tag 'documentable'
  tag legacy: ['SV-106357', 'V-97219']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
