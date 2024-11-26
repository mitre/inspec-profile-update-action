control 'SV-225624' do
  title 'WebSphere MQ channel security is not implemented in accordance with security requirements.'
  desc 'WebSphere MQ channel security can be configured to provide authentication, message privacy, and message integrity between queue managers.  WebSphere MQ channels use SSL encryption techniques, digital signatures and digital certificates to provide message privacy, message integrity and mutual authentication between clients and servers.

Failure to properly secure a WebSphere MQ channel may lead to unauthorized access.  This exposure could compromise the availability, integrity, and confidentiality of some system services, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the z/OS Data Collection:

-	MQSRPT(ssid)

NOTE:	ssid is the queue manager name (a.k.a., subsystem identifier).  To determine which Release of WebSphere MQ, review ssid reports for message CSQU000I.

		Collect the following Information for Websphere MQ queue manager

-	If a WebSphere MQ queue manager communicates with a MQSeries queue manager, provide the WebSphere MQ queue manager and channel names used to connect with MQSeries.
-	If any WebSphere MQ channels are used to communicate within the enclave, provide a list of channels and provide documentation regarding the sensitivity of the information on the channel.

b)	Review the ssid report(s) and perform the following steps:

1)	Find the DISPLAY QMGR SSLKEYR command to locate the start of the Queue Manager definitions.
2)	Verify that each WebSphere MQ 5.3 queue manager is using a digital certificate by reviewing the SSLKEYR parameter to ensure that a keyring is identified.  i.e. SSLKEYR(sslkeyring-id)
3)	Issue the following TSS commands, where ssidCHIN is the Acid for the WebSphere MQ Channel Initiator’s userid and sslkeyring-id is obtained from the above action:

TSS LIST(ssidCHIN) KEYRING(sslkeyring-id)

NOTE: The sslkeyring-id is case sensitive.

In the output find the DIGICERT field for ACID(ssidCHIN).  Use this DIGICERT in the following command:

TSS LIST(ssidCHIN) DIGICERT(digicert)

NOTE: The digicert is case sensitive.

Review the ISSUER DISTINGUISHED NAME field in the resulting output for information of any of the following:

OU=PKI.OU=DoD.O=U.S. Governmemt.C=US
OU=ECA.O=U.S. Government.C=US

4)	Repeat these steps for each queue manager ssid identified.

c)	If the all of the items in (b) above are true, there is NO FINDING.

d)	If any of the items in (b) above are untrue, this is a FINDING.'
  desc 'fix', 'Refer to the following report produced by the z/OS Data Collection:

- MQSRPT(ssid)

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier). 

1)	Find the DISPLAY QMGR SSLKEYR command to locate the start of the Queue Manager definitions.
2)	Verify that each WebSphere MQ queue manager is using a digital certificate by reviewing the SSLKEYR parameter to ensure that a keyring is identified.  i.e. SSLKEYR(sslkeyring-id)
3)	Issue the following TSS commands, where ssidCHIN is the lid for the WebSphere MQ Channel Initiator’s userid and sslkeyring-id is obtain from the above action:

TSS LIST(ssidCHIN) KEYRING(sslkeyring-id)

NOTE: The sslkeyring-id is case sensitive.

In the output find the DIGICERT field for ACID(ssidCHIN).  Use this DIGICERT in the following command:

TSS LIST(ssidCHIN) DIGICERT(digicert)

NOTE: The Certificate Label Name is case sensitive.

Review the Issuer’s Name field in the resulting output for information of any of the following:

OU=PKI.OU=DoD.O=U.S. Governmemt.C=US
OU=ECA.O=U.S. Government.C=US

4)	Repeat these steps for each queue manager ssid identified.

To implement the requirements stated above, the following two items are provided which attempt to assist with (1) Technical "how to" information and (2) A DISA Point of contact for obtaining SSL certificates for CSD WebSphere MQ channels:

1.  Review the information available on setting up SSL, Keyrings, and Digital Certificates in the CA TSS Cookbook regarding usage of the TSS commands to administer PKI Certificates as well as the WebSphere MQ Security manual.  Also review the information contained in the documentation provided as part of the install package from the DISA SSO Resource Management Factory (formerly Software Factory).

2.  For information on obtaining an SSL certificate in the DISA CSD environment, send email inquiry to disaraoperations@disa.mil for more info.'
  impact 0.5
  ref 'DPMS Target zOS WebsphereMQ for TSS'
  tag check_id: 'C-27325r472674_chk'
  tag severity: 'medium'
  tag gid: 'V-225624'
  tag rid: 'SV-225624r472676_rule'
  tag stig_id: 'ZWMQ0012'
  tag gtitle: 'SRG-OS-000403'
  tag fix_id: 'F-27313r472675_fix'
  tag 'documentable'
  tag legacy: ['SV-111901', 'V-6980']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
