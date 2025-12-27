control 'SV-213534' do
  title 'The JBoss server must be configured to restrict access to the web servers private key to authenticated system administrators.'
  desc 'The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user.

Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. Java-based application servers utilize the Java keystore, which provides storage for cryptographic keys and certificates. The keystore is usually maintained in a file stored on the file system.'
  desc 'check', 'The default location for the keystore used by the JBoss vault is the <JBOSS_HOME>/vault/ folder.

If a vault keystore has been created, by default it will be in the file: <JBOSS_HOME>/vault/vault.keystore.  The file stores a single key, with the default alias vault, which will be used to store encrypted strings, such as passwords, for JBoss EAP.

Browse to the JBoss vault folder using the relevant OS commands.
Review the file permissions and ensure only system administrators and JBoss users are allowed access.

Owner can be full access
Group can be full access
All others must be restricted to execute access or no permission.

If non-system administrators are allowed to access the <JBOSS_HOME>/vault/
folder, this is a finding.'
  desc 'fix', 'Configure the application server OS file permissions on the corresponding private key to restrict access to authorized accounts or roles.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14757r296268_chk'
  tag severity: 'medium'
  tag gid: 'V-213534'
  tag rid: 'SV-213534r615939_rule'
  tag stig_id: 'JBOS-AS-000320'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag fix_id: 'F-14755r296269_fix'
  tag 'documentable'
  tag legacy: ['SV-76785', 'V-62295']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
