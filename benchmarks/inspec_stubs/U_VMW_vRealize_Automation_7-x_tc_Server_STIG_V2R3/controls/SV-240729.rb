control 'SV-240729' do
  title 'tc Server VCO must limit the amount of time that each TCP connection is kept alive.'
  desc 'Denial of Service is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests. Mitigation against these threats is to take steps to limit the number of resources that can be consumed in certain ways.

tc Server provides the connectionTimeout attribute. This sets the number of milliseconds tc Server will wait, after accepting a connection, for the request URI line to be presented. This timeout will also be used when reading the request body (if any).'
  desc 'check', 'Navigate to and open /etc/vco/app-server/server.xml.

Navigate to the <Connector> node.

If the value of "connectionTimeout" is not set to "20000" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vco/app-server/server.xml.

Navigate to the <Connector> node.

Configure the <Connector> node with the value 'connectionTimeout="10000"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43962r673929_chk'
  tag severity: 'medium'
  tag gid: 'V-240729'
  tag rid: 'SV-240729r879511_rule'
  tag stig_id: 'VRAU-TC-000025'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-43921r673930_fix'
  tag 'documentable'
  tag legacy: ['SV-100539', 'V-89889']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
