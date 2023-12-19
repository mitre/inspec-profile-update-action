control 'SV-89575' do
  title 'The MQ Appliance messaging server must map the authenticated identity to the individual messaging user or group account for PKI-based authentication.'
  desc 'The cornerstone of PKI is the private key used to encrypt or digitally sign information. The key by itself is a cryptographic value that does not contain specific user information, but the key can be mapped to a user. Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.

Messaging servers must provide the capability to utilize and meet requirements of the DoD Enterprise PKI infrastructure for application authentication.

Note: Two or more alternative LDAP hosts may be listed, in the CONNAME parameter, separated by commas.

Review IBM product documentation for the LDAP fields required when setting up a communication link with the LDAP server.

See https://ibm.biz/BdiBGu for a detailed description of these options.'
  desc 'check', 'To access the MQ Appliance CLI, for each queue manager, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

DIS AUTHINFO(*) AUTHTYPE(CRLLDAP) CONNAME

Verify that an "AUTHINFO" definition of "AUTHTYPE(CRLLDAP)" is displayed and that the CONNAME in parenthesis is the host name or IPv4 dotted decimal address of an organizationally approved LDAP server.

If the "AUTHINFO" definition is not equal to "AUTHTYPE(CRLLDAP)", this is a finding.'
  desc 'fix', %q(Specify LDAP as the authentication method for each queue manager.

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [queue manager name]

DEFINE AUTHINFO('[Object name e.g., USE.CRLLDAP]') 
AUTHTYPE(CRLLDAP) 
CONNAME('[LDAPhost1(port)]') REPLACE

Type "end" to exit runmqsc mode.)
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74901'
  tag rid: 'SV-89575r1_rule'
  tag stig_id: 'MQMH-AS-001020'
  tag gtitle: 'SRG-APP-000177-AS-000126'
  tag fix_id: 'F-81517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
