control 'SV-89421' do
  title 'The MQ Appliance messaging server must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms are used to protect systems requiring the most stringent protection mechanisms." 

NSA-approved cryptography is required to be used for classified information system processing.

The messaging server must utilize NSA-approved encryption modules when protecting classified data. This means using AES and other approved encryption modules.'
  desc 'check', 'Check that TLS mutual authentication has been completed successfully by using DISPLAY commands. If the task was successful, the resulting output is like that shown in the following examples.

For queue manager to queue manager connections:

From queue manager [QM1], enter the following command:

DISPLAY CHS(TO.[QM2]) SSLPEER SSLCERTI

The resulting output should be like the following example:

DISPLAY CHSTATUS(TO.[QM2]) SSLPEER SSLCERTI
4 : DISPLAY CHSTATUS(TO.[QM2]) SSLPEER SSLCERTI
AMQ8417: Display Channel Status details.
CHANNEL(TO.[QM2])             CHLTYPE(SDR)
CONNAME([IP addr QM2])           CURRENT
RQMNAME([QM2])
SSLCERTI("[distinguished name]")
SSLPEER("[distinguished name]")
STATUS(RUNNING)             SUBSTATE(MQGET)
XMITQ([QM2])

From the queue manager [QM2], enter the following command:

DISPLAY CHS(TO.QM2) SSLPEER SSLCERTI

The resulting output is like the following example:

DISPLAY CHSTATUS(TO.[QM2]) SSLPEER SSLCERTI
5 : DISPLAY CHSTATUS(TO.[QM2]) SSLPEER SSLCERTI
AMQ8417: Display Channel Status details.
CHANNEL(TO.[QM2])             CHLTYPE(SDR)
CONNAME([IP addr QM1])           CURRENT
RQMNAME([QM1])
SSLCERTI("[distinguished name]")
SSLPEER("[distinguished name]")
STATUS(RUNNING)             SUBSTATE(MQGET)
XMITQ( )

In each case, the value of "SSLPEER" must match that of the Distinguished Name (DN) in the partner certificate. The issuer name must match the subject DN of the CA certificate that signed the personal certificate.

For client to queue manager connections:

C1=client1, QM1=queue manager 1

From the queue manager [QM1], enter the following command:

DISPLAY CHSTATUS([C1].TO.[QM1]) SSLPEER SSLCERTI

The resulting output is like the following example:

DISPLAY CHSTATUS([C1].TO.[QM1]) SSLPEER SSLCERTI
5 : DISPLAY CHSTATUS([C1].TO.[QM1]) SSLPEER SSLCERTI
AMQ8417: Display Channel Status details.
CHANNEL([C1].TO.[QM1])           CHLTYPE(SVRCONN)
CONNAME([IP addr QM1])           CURRENT
SSLCERTI("[distinguished name]")
SSLPEER("[distinguished name]")
STATUS(RUNNING)             SUBSTATE(RECEIVE)

The "SSLPEER" field in the "DISPLAY CHSTATUS" output shows the subject DN of the remote client certificate. The issuer name matches the subject DN of the CA certificate that signed the personal certificate.

If the connections on each end of the channel are not configured as described above, this is a finding.'
  desc 'fix', "Devices (endpoints) may connect an MQ Appliance MQ queue manager as either remote MQ queue manager or MQ client. In order to ensure unique identification of network-connected devices, mutual authentication using CA-signed TLS certificates should be configured. 

1. Prepare the key repository on each endpoint (client and/or queue manager).
2. Request a CA-signed certificate for each client and/or queue manager. You might use different CAs for the two endpoints.
3. Add the Certificate Authority certificate to the key repository for each client and/or queue manager. If the endpoints are using different Certificate Authorities then the CA certificate for each Certificate Authority must be added to both key repositories.
4. Add the CA-signed certificate to the key repository for each endpoint.

CHOOSE EITHER STEP 5 or 6 BELOW

5. For a queue manager to queue manager connection:
a. On [QM1], define a sender channel and associated transmission queue by issuing commands like the following example:
DEFINE QLOCAL([QM2]) USAGE(XMITQ)
DEFINE CHANNEL(TO.[QM2]) CHLTYPE(SDR) TRPTYPE(TCP) +
CONNAME([QM2 address]) XMITQ([QM2]) SSLCIPH([TLS cipher spec]) +
DESCR('Sender channel using TLS from [QM1] to [QM2]')
The CipherSpecs at each end of the channel must be the same.

b. On [QM2], define a receiver channel by issuing a command like the following example:
DEFINE CHANNEL(TO.[QM2]) CHLTYPE(RCVR) TRPTYPE(TCP) +
SSLCIPH([TLS cipher spec]) SSLCAUTH(REQUIRED) +
DESCR('Receiver channel using TLS to [QM2]')
The channel must have the same name as the sender channel you defined in step 5.a., and use the same CipherSpec.

c. Start the channel.
Ref. Connecting two queue managers using SSL or TLS  https://goo.gl/1GyPRV

6. For a client to queue manager connection:
a. Define a client-connection channel in either of the following ways:
- Using the MQCONNX call with the MQSCO structure on [client]
- Using a client channel definition table

b. On queue manager, define a server-connection channel by issuing a command like the following example:
C1=client 1, MQ1=queue manager 1
DEFINE CHANNEL([C1].TO.[QM1]) CHLTYPE(SVRCONN) TRPTYPE(TCP) +
SSLCIPH(TLS_RSA_WITH_AES_128_CBC_SHA) SSLCAUTH(REQUIRED) +
DESCR('Receiver channel using TLS from [client name] to [QM name]')

The channel must have the same name as the client-connection channel you defined in step 6, and use the same CipherSpec.

Note: Following are the cipher specs available for MQ: https://ibm.biz/BdrJGp"
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74603r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74747'
  tag rid: 'SV-89421r1_rule'
  tag stig_id: 'MQMH-AS-000180'
  tag gtitle: 'SRG-APP-000416-AS-000140'
  tag fix_id: 'F-81363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
