control 'SV-241725' do
  title 'tc Server UI session IDs must be sent to the client using SSL/TLS.'
  desc 'The HTTP protocol is a stateless protocol. To maintain a session, a session identifier is used. The session identifier is a piece of data that is used to identify a session and a user. If the session identifier is compromised by an attacker, the session can be hijacked. By encrypting the session identifier, the identifier becomes more difficult for an attacker to hijack, decrypt, and use before the session has expired.

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vROps should be configured to use modern, secure forms of transport encryption.'
  desc 'check', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml. 

Navigate to each of the <Connector> nodes.

If the value of “sslProtocol” is not set to “TLS” or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> nodes with the setting 'sslProtocol="TLS"')
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-45001r684035_chk'
  tag severity: 'medium'
  tag gid: 'V-241725'
  tag rid: 'SV-241725r879810_rule'
  tag stig_id: 'VROM-TC-000920'
  tag gtitle: 'SRG-APP-000439-WSR-000152'
  tag fix_id: 'F-44960r684036_fix'
  tag 'documentable'
  tag legacy: ['SV-99735', 'V-89085']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
