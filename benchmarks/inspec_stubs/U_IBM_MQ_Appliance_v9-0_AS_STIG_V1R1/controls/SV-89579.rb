control 'SV-89579' do
  title 'The MQ Appliance messaging server must use an enterprise user management system to uniquely identify and authenticate users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated. This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.

To ensure support to the enterprise, the authentication must utilize an enterprise solution.

Review IBM product documentation for the LDAP fields required when setting up a communication link with the LDAP server.

See https://ibm.biz/BdsRRk for a detailed description of these options.'
  desc 'check', 'To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

DIS AUTHINFO(USE.LDAP)

Verify that "AUTHINFO(USE.LDAP)" is displayed under authentication information details. 

If "IBM MQ Appliance object USE.LDAP not found" is displayed, this is a finding.'
  desc 'fix', %q(Specify LDAP as the authentication method for each queue manager.

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [queue manager name]

DEFINE AUTHINFO(USE.LDAP) 
AUTHTYPE(CRLLDAP) 
CONNAME('[host name1(port)],[host name1(port)]') 

ALTER QMGR CONNAUTH('USE.LDAP')
REFRESH SECURITY TYPE(CONNAUTH)

Enter "end" to exit runmqsc mode.)
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74905'
  tag rid: 'SV-89579r1_rule'
  tag stig_id: 'MQMH-AS-001090'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag fix_id: 'F-81521r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
