control 'SV-213529' do
  title 'JBoss management Interfaces must be integrated with a centralized authentication mechanism that is configured to manage accounts according to DoD policy.'
  desc 'JBoss EAP provides a security realm called ManagementRealm.  By default, this realm uses the mgmt-users.properties file for authentication.  Using file-based authentication does not allow the JBoss server to be in compliance with a wide range of user management requirements such as automatic disabling of inactive accounts as per DoD policy.  To address this issue, the management interfaces used to manage the JBoss server must be associated with a security realm that provides centralized authentication management.  Examples are AD or LDAP.

Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Obtain the list of management interfaces by running the command:
"ls /core-service=management/management-interface"

Identify the security realm used by each management interface configuration by running the command:
"ls /core-service=management/management-interface=<MANAGEMENT-INTERFACE-NAME>"

Determine if the security realm assigned to the management interface uses LDAP for authentication by running the command:
"ls /core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication"

If  the security realm assigned to the management interface does not utilize LDAP for authentication, this is a finding.'
  desc 'fix', 'Follow steps in section 11.8 - Management Interface Security in the JBoss_Enterprise_Application_Platform-6.3-Administration_and_Configuration_Guide-en-US document.

1. Create an outbound connection to the LDAP server.
2. Create an LDAP-enabled security realm.
3. Reference the new security domain in the Management Interface.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14752r296253_chk'
  tag severity: 'medium'
  tag gid: 'V-213529'
  tag rid: 'SV-213529r615939_rule'
  tag stig_id: 'JBOS-AS-000290'
  tag gtitle: 'SRG-APP-000163-AS-000111'
  tag fix_id: 'F-14750r296254_fix'
  tag 'documentable'
  tag legacy: ['SV-76775', 'V-62285']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
