control 'SV-89593' do
  title 'The MQ Appliance messaging server must utilize FIPS 140-2 approved encryption modules when authenticating users and processes.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. The use of TLS provides confidentiality of data in transit between the messaging server and client. FIPS 140-2 approved TLS versions include TLS V1.0 or greater. 

TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for government systems.

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
  tag check_id: 'C-74777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74919'
  tag rid: 'SV-89593r1_rule'
  tag stig_id: 'MQMH-AS-001200'
  tag gtitle: 'SRG-APP-000179-AS-000129'
  tag fix_id: 'F-81535r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
