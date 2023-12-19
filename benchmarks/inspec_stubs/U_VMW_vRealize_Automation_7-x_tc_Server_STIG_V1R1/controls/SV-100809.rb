control 'SV-100809' do
  title 'tc Server HORIZON must employ cryptographic mechanisms (TLS/DTLS/SSL) preventing the unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vRA should be configured to use modern, secure forms of transport encryption.'
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml

Navigate to each of the <Connector> nodes.

If the value of "sslProtocol" is not set to "TLS" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Note: There are three <Connector> nodes.

Configure each <Connector> nodes with the setting 'sslProtocol="TLS"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89851r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90159'
  tag rid: 'SV-100809r1_rule'
  tag stig_id: 'VRAU-TC-000860'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-96901r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
