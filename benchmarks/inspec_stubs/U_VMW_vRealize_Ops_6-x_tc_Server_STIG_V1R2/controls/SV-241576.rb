control 'SV-241576' do
  title 'tc Server UI must limit the amount of time that each TCP connection is kept alive.'
  desc 'Denial of Service is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests. Mitigation against these threats is to take steps to limit the number of resources that can be consumed in certain ways.

tc Server provides the “connectionTimeout” attribute. This sets the number of milliseconds tc Server will wait, after accepting a connection, for the request URI line to be presented. This timeout will also be used when reading the request body (if any).'
  desc 'check', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

If the value of “connectionTimeout” is not set to “20000” or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> with the value 'connectionTimeout="20000"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44852r683588_chk'
  tag severity: 'medium'
  tag gid: 'V-241576'
  tag rid: 'SV-241576r879511_rule'
  tag stig_id: 'VROM-TC-000020'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-44811r683589_fix'
  tag 'documentable'
  tag legacy: ['SV-99431', 'V-88781']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
