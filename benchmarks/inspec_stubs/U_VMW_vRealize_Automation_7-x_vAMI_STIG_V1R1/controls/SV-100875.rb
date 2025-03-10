control 'SV-100875' do
  title 'The vAMI private key must only be accessible to authenticated system administrators or the designated PKI Sponsor.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information. If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user. Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. Java-based application servers utilize the Java keystore, which provides storage for cryptographic keys and certificates. The keystore is usually maintained in a file stored on the file system.'
  desc 'check', 'At the command prompt, execute the following command:

ls -l /opt/vmware/etc/sfcb/file.pem

If permissions on the key file are not -r--r----- (440), this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chmod 440 /opt/vmware/etc/sfcb/file.pem'
  impact 0.7
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89917r1_chk'
  tag severity: 'high'
  tag gid: 'V-90225'
  tag rid: 'SV-100875r1_rule'
  tag stig_id: 'VRAU-VA-000250'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag fix_id: 'F-96967r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
