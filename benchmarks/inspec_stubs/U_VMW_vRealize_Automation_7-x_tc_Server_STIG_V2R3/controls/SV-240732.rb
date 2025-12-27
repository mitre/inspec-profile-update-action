control 'SV-240732' do
  title 'tc Server VCO must limit the number of times that each TCP connection is kept alive.'
  desc 'KeepAlive provides long-lived HTTP sessions that allow multiple requests to be sent over the same connection. Enabling KeepAlive mitigates the effects of several types of denial-of-service attacks.

An advantage of KeepAlive is the reduced latency in subsequent requests (no handshaking). However, a disadvantage is that server resources are not available to handle other requests while a connection is maintained between the server and the client.

tc Server can be configured to limit the number of subsequent requests that one client can submit to the server over an established connection. This limit helps provide a balance between the advantages of KeepAlive, while not allowing any one connection being held too long by any one client. maxKeepAliveRequests is the tc Server attribute that sets this limit.'
  desc 'check', 'Navigate to and open /etc/vco/app-server/server.xml.

Navigate to the <Connector> node.

If the value of "maxKeepAliveRequests" is not set to "15" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vco/app-server/server.xml.

Navigate to the <Connector> node.

Configure the <Connector> node with the value 'maxKeepAliveRequests="15"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43965r673938_chk'
  tag severity: 'medium'
  tag gid: 'V-240732'
  tag rid: 'SV-240732r879511_rule'
  tag stig_id: 'VRAU-TC-000040'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-43924r673939_fix'
  tag 'documentable'
  tag legacy: ['SV-100545', 'V-89895']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
