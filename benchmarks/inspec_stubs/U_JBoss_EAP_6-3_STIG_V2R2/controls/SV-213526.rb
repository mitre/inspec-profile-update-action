control 'SV-213526' do
  title 'The JBoss Server must be configured to utilize a centralized authentication mechanism such as AD or LDAP.'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated.  This is typically accomplished via the use of a user store that is either local (OS-based) or centralized (Active Directory/LDAP) in nature.  It should be noted that JBoss does not specifically mention Active Directory since AD is LDAP aware.

To ensure accountability and prevent unauthorized access, the JBoss Server must be configured to utilize a centralized authentication mechanism.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

To obtain the list of security realms run the command:
"ls /core-service=management/security-realm="

Review each security realm using the command:
"ls /core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication"

If this command does not return a security realm that uses LDAP for authentication, this is a finding.'
  desc 'fix', 'Follow steps in section 11.8 - Management Interface Security in the JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US document.

1. Create an outbound connection to the LDAP server.
2. Create an LDAP-enabled security realm.
3. Reference the new security domain in the Management Interface.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14749r296244_chk'
  tag severity: 'medium'
  tag gid: 'V-213526'
  tag rid: 'SV-213526r615939_rule'
  tag stig_id: 'JBOS-AS-000260'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-14747r296245_fix'
  tag 'documentable'
  tag legacy: ['SV-76767', 'V-62277']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
