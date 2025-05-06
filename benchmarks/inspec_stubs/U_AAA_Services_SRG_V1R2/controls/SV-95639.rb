control 'SV-95639' do
  title 'AAA Services must be configured to enforce authorized access to the corresponding private key for PKI-based authentication.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. 

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Verify AAA Services are configured to enforce authorized access to the corresponding private key for PKI-based authentication.

If AAA Services are not configured to enforce authorized access to the corresponding private key, this is a finding.'
  desc 'fix', 'Configure AAA Services to enforce authorized access to the corresponding private key for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80929'
  tag rid: 'SV-95639r1_rule'
  tag stig_id: 'SRG-APP-000176-AAA-000590'
  tag gtitle: 'SRG-APP-000176-AAA-000590'
  tag fix_id: 'F-87785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
