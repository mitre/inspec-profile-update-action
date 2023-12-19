control 'SV-89585' do
  title 'The MQ Appliance messaging server must generate a unique session identifier using a FIPS 140-2 approved random number generator.'
  desc 'The messaging server will use session IDs to communicate between modules or applications within the messaging server and between the messaging server and users. The session ID allows the application to track the communications along with credentials that may have been used to authenticate users or modules.

Unique session IDs are the opposite of sequentially generated session IDs which can be easily guessed by an attacker. Unique session identifiers help to reduce predictability of said identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', 'Check that TLS mutual authentication configuration is correct by using DISPLAY commands. 

To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

DIS CHANNEL(*) CHLTYPE(SVRCONN)

Note the name of SVRCONN channel (client channel) you wish to check.

DIS CHANNEL([name of SVRCONN channel])

Confirm that the parameter "SSLCIPH" specifies the desired cipher spec and that the value of "SSLAUTH" is "REQUIRED".

If either the "SSLCIPH" or "SSLAUTH" value is not correct, this is a finding.'
  desc 'fix', "The most common way devices (endpoints) may connect an MQ Appliance MQ queue manager is as an MQ client. In order to ensure unique identification of network-connected devices, mutual authentication using CA-signed TLS certificates should be configured. 

1. Prepare the key repository on each endpoint client.
2. Request a CA-signed certificate for each client. You might use different CAs for the two endpoints.
3. Add the Certificate Authority certificate to the key repository for each client. If the endpoints are using different Certificate Authorities then the CA certificate for each Certificate Authority must be added to both key repositories.
4. Add the CA-signed certificate to the key repository for each endpoint.

On the MQ Appliance queue manager, define a server-connection channel by issuing a command as in the following example:

[C1]=Client, [QM1]=MQ Appliance queue manager. Replace [QM1] with the actual queue manager name (e.g., FINANCEQM)

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [QM1]
DEFINE CHANNEL([C1].TO.[QM1]) CHLTYPE(SVRCONN) TRPTYPE(TCP) +
SSLCIPH([TLS_RSA_WITH_AES_128_CBC_SHA or other cipher spec]) SSLCAUTH(REQUIRED) +
DESCR('Receiver channel using TLS from [client name] to [QM name]')
end

Note: Following are the cipher specs available for MQ: https://ibm.biz/BdrJGp"
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74911'
  tag rid: 'SV-89585r1_rule'
  tag stig_id: 'MQMH-AS-001150'
  tag gtitle: 'SRG-APP-000224-AS-000152'
  tag fix_id: 'F-81527r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
