control 'SV-224551' do
  title 'WebSphere MQ channel security must be implemented in accordance with security requirements.'
  desc 'WebSphere MQ Channel security can be configured to provide authentication, message privacy, and message integrity between queue managers. Secure Sockets Layer (SSL) uses encryption techniques, digital signatures and digital certificates to provide message privacy, message integrity and mutual authentication between clients and servers.

Failure to properly secure a WebSphere MQ channel may lead to unauthorized access. This exposure could compromise the availability, integrity, and confidentiality of some system services, applications, and customer data.

'
  desc 'check', 'Refer to the following report produced by the z/OS Data Collection:

- MQSRPT(ssid)

NOTE: ssid is the queue manager name (a.k.a., subsystem identifier).

Collect the following Information for WebSphere MQ and MQSeries queue manager.

- If a WebSphere MQ queue manager communicates with a MQSeries queue manager, provide the WebSphere MQ queue manager and channel names used to connect with MQSeries.

Automated Analysis requires Additional Analysis.
Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

- PDI(ZWMQ0011)

If the following guidelines are true for each channel definition displayed from the DISPLAY CHANNEL command, this is not a finding.

___ Verify that each WebSphere MQ channel is using SSL by checking for the SSLCIPH parameter, which must specify a FIPS 140-2 compliant value of the following: (Note: Both ends of the channel must specify the same cipher specification.)

ECDHE_ECDSA_AES_128_CBC_SHA256
ECDHE_ECDSA_AES_256_CBC_SHA384
ECDHE_RSA_AES_128_CBC_SHA256
ECDHE_RSA_AES_256_CBC_SHA384
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA256

___ Repeat the above step for each queue manager ssid identified.'
  desc 'fix', %q(Review the WebSphere MQ Screen interface invoked by the REXX CSQOREXX. Reviewing the channel's SSLCIPH setting.

Display the channel properties and look for the "SSL Cipher Specification" value.

Ensure that a FIPS 140-2 compliant value is shown.

ECDHE_ECDSA_AES_128_CBC_SHA256
ECDHE_ECDSA_AES_256_CBC_SHA384
ECDHE_RSA_AES_128_CBC_SHA256
ECDHE_RSA_AES_256_CBC_SHA384
TLS_RSA_WITH_3DES_EDE_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA
TLS_RSA_WITH_AES_128_CBC_SHA256
TLS_RSA_WITH_AES_256_CBC_SHA
TLS_RSA_WITH_AES_256_CBC_SHA256

Note that both ends of the channel must specify the same cipher specification. 

Repeat these steps for each queue manager ssid identified.)
  impact 0.7
  ref 'DPMS Target zOS WebsphereMQ for RACF'
  tag check_id: 'C-26234r868570_chk'
  tag severity: 'high'
  tag gid: 'V-224551'
  tag rid: 'SV-224551r868574_rule'
  tag stig_id: 'ZWMQ0011'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-26222r868571_fix'
  tag satisfies: ['SRG-OS-000505', 'SRG-OS-000555']
  tag 'documentable'
  tag legacy: ['V-6958', 'SV-7259']
  tag cci: ['CCI-000068', 'CCI-002421', 'CCI-002423', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'SC-8 (3)', 'SC-13 b']
end
