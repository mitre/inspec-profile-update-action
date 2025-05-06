control 'SV-213531' do
  title 'JBoss KeyStore and Truststore passwords must not be stored in clear text.'
  desc 'Access to the JBoss Password Vault must be secured, and the password used to access must be encrypted.  There is a specific process used to generate the encrypted password hash.  This process must be followed in order to store the password in an encrypted format.

The admin must utilize this process in order to ensure the Keystore password is encrypted.'
  desc 'check', 'The default location for the keystore used by the JBoss vault is the <JBOSS_HOME>/vault/ folder.

If a vault keystore has been created, by default it will be in the file: <JBOSS_HOME>/vault/vault.keystore.  The file stores a single key, with the default alias vault, which will be used to store encrypted strings, such as passwords, for JBoss EAP. 

Have the system admin provide the procedure used to encrypt the keystore password that unlocks the keystore.

If the system administrator is unable to demonstrate or provide written process documentation on how to encrypt the keystore password, this is a finding.'
  desc 'fix', 'Configure the application server to mask the java keystore password as per the procedure described in section 11.13.3 -Password Vault System in the JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US document.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14754r296259_chk'
  tag severity: 'medium'
  tag gid: 'V-213531'
  tag rid: 'SV-213531r615939_rule'
  tag stig_id: 'JBOS-AS-000300'
  tag gtitle: 'SRG-APP-000171-AS-000119'
  tag fix_id: 'F-14752r296260_fix'
  tag 'documentable'
  tag legacy: ['SV-76779', 'V-62289']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
