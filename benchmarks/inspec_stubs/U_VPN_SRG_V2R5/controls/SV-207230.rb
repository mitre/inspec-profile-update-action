control 'SV-207230' do
  title 'The IPsec VPN Gateway must use AES encryption for the Internet Key Exchange (IKE) proposal to protect confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

AES is the FIPS-validated cipher block cryptographic algorithm approved for use in DoD. For an algorithm implementation to be listed on a FIPS 140-2 cryptographic module validation certificate as an approved security function, the algorithm implementation must meet all the requirements of FIPS 140-2 and must successfully complete the cryptographic algorithm validation process. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3, CCM, GCM, KW, KWP, and TKW.'
  desc 'check', 'Verify all IKE proposals are set to use the AES encryption algorithm.

View the value of the encryption algorithm for each defined proposal.

If the value of the encryption algorithm for any IKE proposal is not set to use an AES algorithm, this is a finding.'
  desc 'fix', 'Configure the IPsec Gateway to use AES with IKE. The option on the IKE Phase 1 proposal may also be configured to use the  aes-128-cbc, aes-192-cbc, or aes-256-cbc algorithms.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7490r378311_chk'
  tag severity: 'high'
  tag gid: 'V-207230'
  tag rid: 'SV-207230r608988_rule'
  tag stig_id: 'SRG-NET-000317-VPN-001090'
  tag gtitle: 'SRG-NET-000317'
  tag fix_id: 'F-7490r378312_fix'
  tag 'documentable'
  tag legacy: ['V-97139', 'SV-106277']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
