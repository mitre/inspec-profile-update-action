control 'SV-213532' do
  title 'LDAP enabled security realm value allow-empty-passwords must be set to false.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission.  If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Application servers have the capability to utilize either certificates (tokens) or user IDs and passwords in order to authenticate. When the application server transmits or receives passwords, the passwords must be encrypted.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.
Run the command:

"ls /core-service=management/security-realm=ldap_security_realm/authentication=ldap"

If "allow-empty-passwords=true", this is a finding.'
  desc 'fix', 'Configure the LDAP Security Realm using default settings that sets "allow-empty-values" to false.  LDAP Security Realm creation is described in section 11.9 -Add an LDAP Security Realm in the JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US document.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14755r296262_chk'
  tag severity: 'medium'
  tag gid: 'V-213532'
  tag rid: 'SV-213532r615939_rule'
  tag stig_id: 'JBOS-AS-000305'
  tag gtitle: 'SRG-APP-000172-AS-000120'
  tag fix_id: 'F-14753r296263_fix'
  tag 'documentable'
  tag legacy: ['SV-76781', 'V-62291']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
