control 'SV-214672' do
  title 'The Juniper SRX Services Gateway VPN must use AES encryption for the IPsec proposal to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. The Advance Encryption Standard (AES) encryption is critical to ensuring the privacy of the IPsec session; it is imperative that AES is used for encryption operations.

Remote access is access to DoD-non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections.

While there is much debate about the security and performance of AES, there is a consensus that AES is significantly more secure than other algorithms currently supported by IPsec implementations. AES is available in three key sizes: 128, 192, and 256 bits, versus the 56 bit DES. Therefore, there are approximately 1021 times more AES 128-bit keys than DES 56-bit keys. In addition, AES uses a block size of 128 bits—twice the size of DES or 3DES.'
  desc 'check', 'Verify all Internet Key Exchange (IKE) proposals are set to use the AES encryption algorithm.

[edit]
show security ipsec

View the value of the encryption algorithm for each defined proposal.

If the value of the encryption algorithm for any IPsec proposal is not set to use an AES algorithm, this is a finding.'
  desc 'fix', 'The following example commands configure the IPsec (phase 2) proposals. The option may also be configured to use the aes-128-cbc, aes-192-cbc, or aes-256-cbc algorithms.

[edit]
set security ipsec proposal <IPSEC-PROPOSAL-NAME> encryption-algorithm aes-256-cbc'
  impact 0.7
  ref 'DPMS Target Juniper SRX Services Gateway VPN'
  tag check_id: 'C-15873r297603_chk'
  tag severity: 'high'
  tag gid: 'V-214672'
  tag rid: 'SV-214672r382783_rule'
  tag stig_id: 'JUSX-VN-000005'
  tag gtitle: 'SRG-NET-000062'
  tag fix_id: 'F-15871r297604_fix'
  tag 'documentable'
  tag legacy: ['V-66021', 'SV-80511']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
