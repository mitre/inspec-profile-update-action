control 'SV-239979' do
  title 'The Cisco VPN remote access server must be configured to use AES encryption for the Internet Key Exchange (IKE) Phase 1 to protect confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

AES is the FIPS-validated cipher block cryptographic algorithm approved for use in DoD. For an algorithm implementation to be listed on a FIPS 140-2 cryptographic module validation certificate as an approved security function, the algorithm implementation must meet all the requirements of FIPS 140-2 and must successfully complete the cryptographic algorithm validation process. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3, CCM, GCM, KW, KWP, and TKW.'
  desc 'check', 'Verify IKE Phase 1 is set to use an AES encryption algorithm as shown in the example below.

crypto ipsec ikev2 ipsec-proposal IPSEC_TRANS
 protocol esp encryption aes-192

If the value of the encryption algorithm for IKE Phase 1 is not set to use an AES algorithm, this is a finding.'
  desc 'fix', 'Configure the ASA to use AES encryption algorithm for IKE Phase 1 as shown in the example below.

ASA1(config)# crypto ikev2 policy 1
ASA1(config-ikev2-policy)# encryption aes-192'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43212r666341_chk'
  tag severity: 'high'
  tag gid: 'V-239979'
  tag rid: 'SV-239979r666343_rule'
  tag stig_id: 'CASA-VN-000640'
  tag gtitle: 'SRG-NET-000317-VPN-001090'
  tag fix_id: 'F-43171r666342_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
