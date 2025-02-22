control 'SV-89537' do
  title 'The MQ Appliance messaging server must protect the confidentiality and integrity of transmitted information through the use of an approved TLS version.'
  desc 'Preventing the disclosure of transmitted information requires that the messaging server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission.  This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the messaging server and a large number of devices/applications external to the messaging server.  Examples are a web client used by a user, a backend database, a log server, or other messaging servers (and clients) in a messaging server cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure.  The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.

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
  tag check_id: 'C-74721r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74863'
  tag rid: 'SV-89537r1_rule'
  tag stig_id: 'MQMH-AS-001230'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag fix_id: 'F-81479r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
