control 'SV-82891' do
  title 'The Mainframe Product, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user. 

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configurations do not enforce authorized access to the corresponding private key when using PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to enforce authorized access to the corresponding private key when using PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68401'
  tag rid: 'SV-82891r1_rule'
  tag stig_id: 'SRG-APP-000176-MFP-000243'
  tag gtitle: 'SRG-APP-000176-MFP-000243'
  tag fix_id: 'F-74517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
