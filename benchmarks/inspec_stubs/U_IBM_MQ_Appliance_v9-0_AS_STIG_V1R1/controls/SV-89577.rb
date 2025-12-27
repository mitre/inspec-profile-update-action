control 'SV-89577' do
  title 'The MQ Appliance must disable identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications. Attackers that are able to exploit an inactive identifier can potentially obtain and maintain undetected access to the application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 

Applications need to track periods of inactivity and disable application identifiers after 35 days of inactivity. 

Management of user identifiers is not applicable to shared information system accounts (e.g., guest and anonymous accounts). It is commonly the case that a user account is the name of an information system account associated with an individual.

To avoid having to build complex user management capabilities directly into their application, wise developers leverage the underlying OS or other user account management infrastructure (AD, LDAP) that is already in place within the organization and meets organizational user account management requirements.

Review IBM product documentation for the LDAP fields required when setting up a communication link with the LDAP server.

Note: Multiple alternative LDAP hosts may be listed in the CONNAME parameter, separated by commas.

Review IBM product documentation for the LDAP fields required when setting up a communication link with the LDAP server.

See https://ibm.biz/BdiBGu and https://ibm.biz/BdixXz for a detailed description of these options.'
  desc 'check', 'To access the MQ Appliance CLI, for each queue manager, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

To display the active authentication object, enter:
DIS QMGR CONNAUTH

Result: QMNAME([queue mgr name]) CONNAUTH([auth object name])

DIS AUTHINFO(auth object name)

Verify that "AUTHTYPE(IDPWLDAP)" is displayed.

Verify LDAP server user settings are configured to disable accounts after "35" days of inactivity.

If "AUTHTYPE(IDPWLDAP)" is not displayed or if the LDAP server user settings are not configured to disable accounts after "35" days of inactivity, this is a finding.'
  desc 'fix', %q(Specify LDAP as the authentication method for each queue manager.

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [queue manager name]

DEFINE AUTHINFO('[Object name e.g., USE.LDAP]') 
AUTHTYPE(IDPWLDAP) 
CONNAME('[ldap1(port),ldap2(port),ldap3(port)]')  
SECCOMM(YES)                                 [Ensures encryption is used]
SHORTUSR('[short user name]') 
CHCKCLNT(REQUIRED) 
BASEDNU('base user DN') 
REPLACE

ALTER QMGR CONNAUTH('[AUTHINFO object name]')
REFRESH SECURITY TYPE(CONNAUTH)

Enter "end" to exit runmqsc mode.

Configure LDAP server to disable accounts after 35 days of inactivity.)
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74903'
  tag rid: 'SV-89577r1_rule'
  tag stig_id: 'MQMH-AS-001080'
  tag gtitle: 'SRG-APP-000163-AS-000111'
  tag fix_id: 'F-81519r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
