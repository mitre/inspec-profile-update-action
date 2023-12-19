control 'SV-239980' do
  title 'The Cisco ASA VPN remote access server must be configured to use AES256 or greater encryption for the IPsec security association to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

A block cipher mode is an algorithm that features the use of a symmetric key block cipher algorithm to provide an information service, such as confidentiality or authentication.

AES is the FIPS-validated cipher block cryptographic algorithm approved for use in DOD. For an algorithm implementation to be listed on a FIPS 140-2/140-3 cryptographic module validation certificate as an approved security function, the algorithm implementation must meet all the requirements of FIPS 140-2/140-3 and must successfully complete the cryptographic algorithm validation process. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3, CCM, GCM, KW, KWP, and TKW.'
  desc 'check', 'Verify all IPsec proposals are set to use the AES256 or greater encryption algorithm as shown in the example below.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp encryption aes-256

If the value of the encryption algorithm for any IPsec proposal is not set to use an AES256 or greater algorithm, this is a finding.'
  desc 'fix', 'Configure the ASA to use AES256 or greater encryption algorithm to implement IPsec encryption services as shown in the example below.

ASA2(config)# crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
ASA2(config-ipsec-proposal)# protocol esp encryption aes-256
ASA2(config-ipsec-proposal)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43213r916141_chk'
  tag severity: 'high'
  tag gid: 'V-239980'
  tag rid: 'SV-239980r916158_rule'
  tag stig_id: 'CASA-VN-000650'
  tag gtitle: 'SRG-NET-000525-VPN-002330'
  tag fix_id: 'F-43172r916142_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
