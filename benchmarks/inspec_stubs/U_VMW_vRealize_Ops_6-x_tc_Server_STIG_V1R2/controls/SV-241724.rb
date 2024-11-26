control 'SV-241724' do
  title 'tc Server API must employ cryptographic mechanisms (TLS/DTLS/SSL) preventing the unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. vROps should be configured to use modern, secure forms of transport encryption.'
  desc 'check', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to the <Connector> node that contains [port="${vmware-ssl.https.port}"].

If the value of “sslProtocol” is not set to “TLS” or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to the <Connector> node that contains 'port="${vmware-ssl.https.port}"'.

Add the setting 'sslProtocol="TLS"')
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-45000r684032_chk'
  tag severity: 'medium'
  tag gid: 'V-241724'
  tag rid: 'SV-241724r928837_rule'
  tag stig_id: 'VROM-TC-000915'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-44959r684033_fix'
  tag 'documentable'
  tag legacy: ['SV-99733', 'V-89083']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
