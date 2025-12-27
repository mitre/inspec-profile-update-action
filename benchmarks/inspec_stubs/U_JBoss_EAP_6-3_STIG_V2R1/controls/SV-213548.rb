control 'SV-213548' do
  title 'JBoss must be configured to use an approved cryptographic algorithm in conjunction with TLS.'
  desc 'Preventing the disclosure or modification of transmitted information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSec tunnel.

If data in transit is unencrypted, it is vulnerable to disclosure and modification. If approved cryptographic algorithms are not used, encryption strength cannot be assured.

FIPS 140-2 approved TLS versions include TLS V1.2 or greater.

TLS must be enabled, and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Log on to the OS of the JBoss server with OS permissions that allow access to JBoss.
Using the relevant OS commands and syntax, cd to the <JBOSS_HOME>/bin/ folder.
Run the jboss-cli script.
Connect to the server and authenticate.

Validate that the TLS protocol is used for HTTPS connections.
Run the command:

"ls /subsystem=web/connector=https/ssl=configuration"

Review the cipher suites.  The following suites are acceptable as per NIST 800-52r1 section 3.3.1 - Cipher Suites.  Refer to the NIST document for a complete list of acceptable cipher suites.  The source NIST document and approved encryption algorithms/cipher suites are subject to change and should be referenced.

AES_128_CBC
AES_256_CBC
AES_128_GCM
AES_128_CCM
AES_256_CCM

If the cipher suites utilized by the TLS server are not approved by NIST as per 800-52r1, this is a finding.'
  desc 'fix', "Reference section 4.6 of the JBoss EAP 6.3 Security Guide located on the Red Hat vendor's website for step-by-step instructions on establishing SSL encryption on JBoss.

The overall steps include:

1. Add an HTTPS connector.
2. Configure the SSL encryption certificate and keys.
3. Set the Cipher to an approved algorithm."
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14771r296310_chk'
  tag severity: 'medium'
  tag gid: 'V-213548'
  tag rid: 'SV-213548r615939_rule'
  tag stig_id: 'JBOS-AS-000655'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-14769r296311_fix'
  tag 'documentable'
  tag legacy: ['SV-76813', 'V-62323']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
