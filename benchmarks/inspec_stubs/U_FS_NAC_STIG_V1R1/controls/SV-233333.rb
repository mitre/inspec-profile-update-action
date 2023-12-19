control 'SV-233333' do
  title 'Forescout that stores device keys must have a key management process that is FIPS-approved and protected by Advanced Encryption Standard (AES) block cipher algorithms.'
  desc "The NAC that stores secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys. Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the authorized device and gain access to the network.

Private key data associated with software certificates, including those issued to a NAC, are required to be generated and protected in at least a FIPS 140-2 Level 1-validated cryptographic module."
  desc 'check', 'If the NAC does not store device keys, this is not applicable.

Verify the NAC is configured to use FIPS-mode or a key management process that is protected by Advanced Encryption Standard (AES) block cipher algorithms.

If the NAC does not use FIPS-mode or key management process that is FIPS-approved and protected by Advanced Encryption Standard (AES) block cipher algorithms, this is a finding.'
  desc 'fix', 'If the Forescout Appliance is using FIPS mode, then TLS 1.2 is set as part of that configuration and does not need to be configured manually. 

If not in FIPS mode, then:
1. Select Tools >> Option >> HPS Inspection Engine >> SecureConnector.
2. In the Client-Server Connection, set the Minimum Supported TLS Version to TLS version 1.2.'
  impact 0.7
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36528r605702_chk'
  tag severity: 'high'
  tag gid: 'V-233333'
  tag rid: 'SV-233333r611394_rule'
  tag stig_id: 'FORE-NC-000280'
  tag gtitle: 'SRG-NET-000525-NAC-002430'
  tag fix_id: 'F-36493r605703_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
