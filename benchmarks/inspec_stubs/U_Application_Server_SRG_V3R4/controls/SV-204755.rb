control 'SV-204755' do
  title 'Only authenticated system administrators or the designated PKI Sponsor for the application server must have access to the web servers private key.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. 

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user. 

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. Java-based application servers utilize the Java keystore, which provides storage for cryptographic keys and certificates. The keystore is usually maintained in a file stored on the file system.'
  desc 'check', 'Review application server configuration and documentation to ensure the application server enforces authorized access to the corresponding private key.

If the application server is not configured to enforce authorized access to the corresponding private key, this is a finding.'
  desc 'fix', 'Configure the application server to enforce authorized access to the corresponding private key.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4875r282912_chk'
  tag severity: 'medium'
  tag gid: 'V-204755'
  tag rid: 'SV-204755r879613_rule'
  tag stig_id: 'SRG-APP-000176-AS-000125'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-4875r282913_fix'
  tag 'documentable'
  tag legacy: ['SV-46611', 'V-35324']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
