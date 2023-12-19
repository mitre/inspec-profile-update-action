control 'SV-89587' do
  title 'The MQ Appliance messaging server must authenticate all network-connected endpoint devices before establishing any connection.'
  desc 'Device authentication requires unique identification and authentication that may be defined by type, by specific device, or by a combination of type and device.

Device authentication is accomplished via the use of certificates and protocols such as SSL mutual authentication.

Device authentication is performed when the messaging server is providing web services capabilities and data protection requirements mandate the need to establish the identity of the connecting device before the connection is established.

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
  desc 'fix', %q(The most common way devices (endpoints) may connect an MQ Appliance MQ queue manager is as an MQ client. In order to ensure unique identification of network-connected devices, mutual authentication using CA-signed TLS certificates should be configured. 

1. Prepare the key repository on each endpoint client.
2. Request a CA-signed certificate for each client. You might use different CAs for the two endpoints.
3. Add the Certificate Authority certificate to the key repository for each client. If the endpoints are using different Certificate Authorities then the CA certificate for each Certificate Authority must be added to both key repositories.
4. Add the CA-signed certificate to the key repository for each endpoint.

On the MQ Appliance queue manager, define a server-connection channel by issuing a command as in the following example:

[C1]=Client, [QM1]=MQ Appliance queue manager. Replace [QM1] with the actual queue manager name (e.g., FINANCEQM)

To access the MQ Appliance CLI, enter:
mqcli

runmqsc [QM1]

Replace the brackets "[ ]" with a selected parameter:
DEFINE CHANNEL([C1].TO.[QM1]) CHLTYPE(SVRCONN) TRPTYPE(TCP) +
SSLCIPH([TLS_RSA_WITH_AES_128_CBC_SHA or other cipher spec]) SSLCAUTH(REQUIRED) +
DESCR('Receiver channel using TLS from [client name] to [QM name]')

For example:
ALTER CHANNEL(C1.TO.QM1) CHLTYPE(SVRCONN) TRPTYPE(TCP) +
SSLCIPH(TLS_RSA_WITH_AES_128_CBC_SHA) SSLCAUTH(REQUIRED) +
DESCR('Receiver channel using TLS from C1 to QM1'))
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74771r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74913'
  tag rid: 'SV-89587r1_rule'
  tag stig_id: 'MQMH-AS-001160'
  tag gtitle: 'SRG-APP-000394-AS-000241'
  tag fix_id: 'F-81529r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
