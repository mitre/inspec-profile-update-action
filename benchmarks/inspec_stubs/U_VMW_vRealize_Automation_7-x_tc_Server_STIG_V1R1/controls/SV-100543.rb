control 'SV-100543' do
  title 'tc Server HORIZON must limit the number of times that each TCP connection is kept alive.'
  desc 'KeepAlive provides long lived HTTP sessions that allow multiple requests to be sent over the same connection. Enabling KeepAlive mitigates the effects of several types of denial-of-service attacks.

An advantage of KeepAlive is the reduced latency in subsequent requests (no handshaking). However, a disadvantage is that server resources are not available to handle other requests while a connection is maintained between the server and the client.

tc Server can be configured to limit the number of subsequent requests that one client can submit to the server over an established connection. This limit helps provide a balance between the advantages of KeepAlive, while not allowing any one connection being held too long by any one client. maxKeepAliveRequests is the tc Server attribute that sets this limit.'
  desc 'check', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of "maxKeepAliveRequests" is not set to "15" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value 'maxKeepAliveRequests="15"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89893'
  tag rid: 'SV-100543r1_rule'
  tag stig_id: 'VRAU-TC-000035'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-96635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
