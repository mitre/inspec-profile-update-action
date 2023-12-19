control 'SV-89591' do
  title 'MQ Appliance messaging servers must use NIST-approved or NSA-approved key management technology and processes.'
  desc 'An asymmetric encryption key must be protected during transmission. The public portion of an asymmetric key pair can be freely distributed without fear of compromise, and the private portion of the key must be protected. The messaging server will provide software libraries that applications can programmatically utilize to encrypt and decrypt information. These messaging server libraries must use NIST-approved or NSA-approved key management technology and processes when producing, controlling, or distributing symmetric and asymmetric keys.

The most common way devices (endpoints) may connect an MQ Appliance MQ queue manager is as an MQ client. In order to ensure unique identification of network-connected devices, mutual authentication using CA-signed TLS certificates should be configured. 

Note: Following are the cipher specs available for MQ: https://ibm.biz/BdrJGp'
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
  desc 'fix', "1. Prepare the key repository on each endpoint client.
2. Request a CA-signed certificate for each client. You might use different CAs for the two endpoints.
3. Add the Certificate Authority certificate to the key repository for each client. If the endpoints are using different Certificate Authorities then the CA certificate for each Certificate Authority must be added to both key repositories.
4. Add the CA-signed certificate to the key repository for each endpoint.

On the MQ Appliance queue manager, define a server-connection channel by issuing a command as in the following example:

[C1]=Client, [QM1]=MQ Appliance queue manager. Replace [QM1] with the actual queue manager name (e.g., FINANCEQM)

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [QM1]

DEFINE CHANNEL([C1].TO.[QM1]) CHLTYPE(SVRCONN) TRPTYPE(TCP) 
SSLCIPH([TLS_RSA_WITH_AES_128_CBC_SHA or other cipher spec]) SSLCAUTH(REQUIRED) 
DESCR('Receiver channel using TLS from [client name] to [QM name]')
end"
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74917'
  tag rid: 'SV-89591r1_rule'
  tag stig_id: 'MQMH-AS-001180'
  tag gtitle: 'SRG-APP-000514-AS-000136'
  tag fix_id: 'F-81533r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
