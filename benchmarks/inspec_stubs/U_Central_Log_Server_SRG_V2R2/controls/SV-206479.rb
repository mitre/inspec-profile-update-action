control 'SV-206479' do
  title 'The Central Log Server, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. 

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'If not using PKI-based authentication this is NA.

Examine the configuration.

Verify the Central Log Server is configured to enforce authorized access to the corresponding private key when using PKI-based authentication.

If the Central Log Server is not configured to enforce authorized access to the corresponding private key when using PKI-based authentication, this is a finding.'
  desc 'fix', 'If using PKI-based authentication, configure the Central Log Server to enforce authorized access to the corresponding private key.'
  impact 0.7
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6739r285681_chk'
  tag severity: 'high'
  tag gid: 'V-206479'
  tag rid: 'SV-206479r397597_rule'
  tag stig_id: 'SRG-APP-000176-AU-002640'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-6739r285682_fix'
  tag 'documentable'
  tag legacy: ['SV-96003', 'V-81289']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
