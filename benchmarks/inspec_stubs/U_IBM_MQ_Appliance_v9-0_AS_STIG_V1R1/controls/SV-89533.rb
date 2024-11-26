control 'SV-89533' do
  title 'The MQ Appliance messaging server must employ approved cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Preventing the disclosure or modification of transmitted information requires that messaging servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel.

If data in transit is unencrypted, it is vulnerable to disclosure and modification. If approved cryptographic algorithms are not used, encryption strength cannot be assured.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.

TLS must be enabled and non-FIPS-approved SSL versions must be disabled.  NIST SP 800-52 specifies the preferred configurations for government systems.

To achieve FIPS 140-2 compliance on Windows, UNIX, and Linux systems, all key repositories have been created and manipulated using only FIPS-compliant software, such as runmqakm with the -fips option.'
  desc 'check', 'To access the MQ Appliance CLI, enter:
mqcli

To identify the queue managers, enter:
dspmq

For each queue manager identified, run the command:
runmqsc [queue name]

DIS QMGR SSLFIPS

If the value of "SSLFIPS" is set to "NO", this is a finding.'
  desc 'fix', 'To access the MQ Appliance CLI, for each queue manager, enter:

mqcli

runmqsc [queue manager name]
ALTER QMGR SSLFIPS(YES)
end'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 AS'
  tag check_id: 'C-74717r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74859'
  tag rid: 'SV-89533r1_rule'
  tag stig_id: 'MQMH-AS-001250'
  tag gtitle: 'SRG-APP-000440-AS-000167'
  tag fix_id: 'F-81475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
