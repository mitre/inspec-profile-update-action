control 'SV-213530' do
  title 'The JBoss Password Vault must be used for storing passwords or other sensitive configuration information.'
  desc 'JBoss EAP 6 has a Password Vault to encrypt sensitive strings, store them in an encrypted keystore, and decrypt them for applications and verification systems. Plain-text configuration files, such as XML deployment descriptors, need to specify passwords and other sensitive information. Use the JBoss EAP Password Vault to securely store sensitive strings in plain-text files.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss. 

Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/standalone/configuration folder.  Review the standalone.xml file. 

Locate the <vault> section. 

If the <vault> section does not exist or if the <vault-option> settings are not configured, this is a finding.'
  desc 'fix', 'Configure the application server to use the java keystore and JBoss vault as per section 11.13.1 -Password Vault System in the JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US document.

1. Create a java keystore.
2. Mask the keystore password and initialize the password vault.
3. Configure JBoss to use the password vault.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14753r296256_chk'
  tag severity: 'medium'
  tag gid: 'V-213530'
  tag rid: 'SV-213530r615939_rule'
  tag stig_id: 'JBOS-AS-000295'
  tag gtitle: 'SRG-APP-000171-AS-000119'
  tag fix_id: 'F-14751r296257_fix'
  tag 'documentable'
  tag legacy: ['SV-76777', 'V-62287']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
