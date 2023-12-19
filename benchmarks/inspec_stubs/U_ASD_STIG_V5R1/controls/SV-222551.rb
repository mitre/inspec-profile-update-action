control 'SV-222551' do
  title 'The application, when using PKI-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If the private key is discovered, an attacker can use the key to authenticate as an authorized user and gain access to the network infrastructure.

The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys.'
  desc 'check', "Review the application documentation and interview the application administrator to identify where the application's private key is stored.

If the application does not perform code signing or other cryptographic tasks requiring a private key, this requirement is not applicable.

Ask the administrator to demonstrate where the application private key(s) are stored. Examine access restrictions and ensure access controls are in place to restrict access to the private key(s).

If the key(s) are stored on the file system, ensure adequate file permissions are set so as to only allow authorized users and processes.

If the key(s) are maintained or available via an application interface, ensure the application provides access controls that limit access via the application interface to only authorized users and processes.

Review access controls and attempt to use a relevant user account, group or application role that is not allowed access to the private key.

Verify access to the keys is denied.

If unauthorized access is granted to the private key(s), this is a finding."
  desc 'fix', 'Configure the application or relevant access control mechanism to enforce authorized access to the application private key(s).'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24221r493561_chk'
  tag severity: 'high'
  tag gid: 'V-222551'
  tag rid: 'SV-222551r508029_rule'
  tag stig_id: 'APSC-DV-001820'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-24210r493562_fix'
  tag 'documentable'
  tag legacy: ['SV-84773', 'V-70151']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
