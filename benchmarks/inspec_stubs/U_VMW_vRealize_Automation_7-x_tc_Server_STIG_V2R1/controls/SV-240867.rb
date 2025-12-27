control 'SV-240867' do
  title 'tc Server HORIZON session IDs must be sent to the client using SSL/TLS.'
  desc 'The HTTP protocol is a stateless protocol. To maintain a session, a session identifier is used. The session identifier is a piece of data that is used to identify a session and a user. If the session identifier is compromised by an attacker, the session can be hijacked. By encrypting the session identifier, the identifier becomes more difficult for an attacker to hijack, decrypt, and use before the session has expired.

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vRA should be configured to use modern, secure forms of transport encryption.'
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of "sslProtocol" is not set to "TLS" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Note: There are three <Connector> nodes.

Configure each <Connector> nodes with the setting 'sslProtocol="TLS"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44100r674343_chk'
  tag severity: 'medium'
  tag gid: 'V-240867'
  tag rid: 'SV-240867r674345_rule'
  tag stig_id: 'VRAU-TC-000870'
  tag gtitle: 'SRG-APP-000439-WSR-000152'
  tag fix_id: 'F-44059r674344_fix'
  tag 'documentable'
  tag legacy: ['SV-100813', 'V-90163']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
