control 'SV-207257' do
  title 'The IPsec VPN must use Advanced Encryption Standard (AES) encryption for the IPsec proposal to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

A block cipher mode is an algorithm that features the use of a symmetric key block cipher algorithm to provide an information service, such as confidentiality or authentication.

AES is the FIPS-validated cipher block cryptographic algorithm approved for use in DoD. For an algorithm implementation to be listed on a FIPS 140-2 cryptographic module validation certificate as an approved security function, the algorithm implementation must meet all the requirements of FIPS 140-2 and must successfully complete the cryptographic algorithm validation process. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3, CCM, GCM, KW, KWP, and TKW.'
  desc 'check', 'Verify all Internet Key Exchange (IKE) proposals are set to use the AES encryption algorithm.

View the value of the encryption algorithm for each defined proposal.

If the value of the encryption algorithm for any IPsec proposal is not set to use an AES algorithm, this is a finding.'
  desc 'fix', 'Configure the IPsec Gateway to use AES for the IPsec proposal. The following example commands configure the IPsec (phase 2) proposals. The option may also be configured to use the aes-128-cbc, aes-192-cbc, or aes-256-cbc algorithms.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7517r378392_chk'
  tag severity: 'high'
  tag gid: 'V-207257'
  tag rid: 'SV-207257r608988_rule'
  tag stig_id: 'SRG-NET-000525-VPN-002330'
  tag gtitle: 'SRG-NET-000525'
  tag fix_id: 'F-7517r378393_fix'
  tag 'documentable'
  tag legacy: ['SV-106347', 'V-97209']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
