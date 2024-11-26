control 'SV-234380' do
  title 'The UEM server, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. 

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. 

Satisfies:FIA_X509_EXT.1.1(1)'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the he UEM server, when using PKI-based authentication, enforces authorized access to the corresponding private key.

If the UEM server, when using PKI-based authentication, does not enforce authorized access to the corresponding private key, this is a finding'
  desc 'fix', 'Configure the UEM server, when using PKI-based authentication, to enforce authorized access to the corresponding private key.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37565r614150_chk'
  tag severity: 'medium'
  tag gid: 'V-234380'
  tag rid: 'SV-234380r617355_rule'
  tag stig_id: 'SRG-APP-000176-UEM-000107'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-37530r614151_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
