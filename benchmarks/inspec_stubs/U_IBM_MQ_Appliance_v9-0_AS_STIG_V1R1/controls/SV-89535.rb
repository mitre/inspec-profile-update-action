control 'SV-89535' do
  title 'The MQ Appliance messaging server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the messaging server, the client sends a list of supported cipher suites in order of preference.  The messaging server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the messaging server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.

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
  tag check_id: 'C-74719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74861'
  tag rid: 'SV-89535r1_rule'
  tag stig_id: 'MQMH-AS-001240'
  tag gtitle: 'SRG-APP-000439-AS-000274'
  tag fix_id: 'F-81477r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
