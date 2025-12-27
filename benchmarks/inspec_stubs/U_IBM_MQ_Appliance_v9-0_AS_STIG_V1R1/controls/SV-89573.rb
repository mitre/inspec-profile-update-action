control 'SV-89573' do
  title 'Access to the MQ Appliance messaging server must utilize encryption when using LDAP for authentication.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords during transmission. 

Messaging servers have the capability to utilize LDAP directories for authentication. If LDAP connections are not protected during transmission, sensitive authentication credentials can be stolen. When the messaging server utilizes LDAP, the LDAP traffic must be encrypted.

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

Verify that "AUTHTYPE(IDPWLDAP)", and "SECCOMM(YES)" are displayed, and that all parameters are correctly specified to use the organizationally approved LDAP server(s).

If these parameter values cannot be verified, this is a finding.'
  desc 'fix', %q(Specify LDAP as the authentication method for each queue manager.

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [queue manager name]

DEFINE AUTHINFO('[Object name e.g., USE.LDAP]') 
AUTHTYPE(IDPWLDAP) 
CONNAME('[ldap1(port),ldap2(port),ldap3(port)]') 
SECCOMM(YES) [Ensures encryption is used]
SHORTUSR('[short user name]') 
CHCKCLNT(REQUIRED) 
BASEDNU('base user DN') 
REPLACE

ALTER QMGR CONNAUTH('[AUTHINFO object name]')
REFRESH SECURITY TYPE(CONNAUTH)

Type "end" to exit runmqsc mode.)
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74899'
  tag rid: 'SV-89573r1_rule'
  tag stig_id: 'MQMH-AS-001010'
  tag gtitle: 'SRG-APP-000172-AS-000121'
  tag fix_id: 'F-81515r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
