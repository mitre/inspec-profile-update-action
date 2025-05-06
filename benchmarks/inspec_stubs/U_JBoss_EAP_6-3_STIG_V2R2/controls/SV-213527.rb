control 'SV-213527' do
  title 'The JBoss Server must be configured to use certificates to authenticate admins.'
  desc 'Multifactor authentication creates a layered defense and makes it more difficult for an unauthorized person to access the application server.  If one factor is compromised or broken, the attacker still has at least one more barrier to breach before successfully breaking into the target.  Unlike a simple username/password scenario where the attacker could gain access by knowing both the username and password without the user knowing his account was compromised, multifactor authentication adds the requirement that the attacker must have something from the user, such as a token, or to biometrically be the user.

Multifactor authentication is defined as: using two or more factors to achieve authentication.

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). A CAC or PKI Hardware Token meets this definition.

A privileged account is defined as an information system account with authorizations of a privileged user.  These accounts would be capable of accessing the web management interface.

When accessing the application server via a network connection, administrative access to the application server must be PKI Hardware Token enabled or a DoD-approved soft certificate.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Follow these steps:
1. Identify the security realm assigned to the management interfaces by using the following command:

For standalone systems:
"ls  /core-service=management/management-interface=<INTERFACE-NAME>"

For managed domain systems:
"ls  /host=master/core-service=management/management-interface=<INTERFACE-NAME>"

Document the name of the security-realm associated with each management interface.

2. Review the security realm using the command:

For standalone systems:
"ls /core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication"

For managed domains:
"ls /host=master/core-service=management/security-realm=<SECURITY_REALM_NAME>/authentication"

If the command in step 2 does not return a security realm that uses certificates for authentication, this is a finding.'
  desc 'fix', 'Configure the application server to authenticate privileged users via multifactor/certificate-based authentication mechanisms when using network access to the management interface.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14750r296247_chk'
  tag severity: 'medium'
  tag gid: 'V-213527'
  tag rid: 'SV-213527r615939_rule'
  tag stig_id: 'JBOS-AS-000265'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag fix_id: 'F-14748r296248_fix'
  tag 'documentable'
  tag legacy: ['SV-76769', 'V-62279']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
