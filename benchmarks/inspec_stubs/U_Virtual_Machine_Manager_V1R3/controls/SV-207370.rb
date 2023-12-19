control 'SV-207370' do
  title 'The VMM, for PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', 'Verify the VMM, for PKI-based authentication, enforces authorized access to the corresponding private key.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM, for PKI-based authentication, to enforce authorized access to the corresponding private key.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7627r365520_chk'
  tag severity: 'medium'
  tag gid: 'V-207370'
  tag rid: 'SV-207370r378733_rule'
  tag stig_id: 'SRG-OS-000067-VMM-000340'
  tag gtitle: 'SRG-OS-000067'
  tag fix_id: 'F-7627r365521_fix'
  tag 'documentable'
  tag legacy: ['V-56927', 'SV-71187']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
