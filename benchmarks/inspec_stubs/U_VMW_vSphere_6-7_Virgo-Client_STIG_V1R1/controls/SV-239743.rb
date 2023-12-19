control 'SV-239743' do
  title 'vSphere Client must limit the amount of time that each TCP connection is kept alive.'
  desc 'Denial of service (DoS) is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests. 

In Virgo, the "connectionTimeout" attribute sets the number of milliseconds the server will wait after accepting a connection for the request URI line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.

'
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector[@port="9090"]/@connectionTimeout' /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

connectionTimeout="20000"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

Configure each <Connector> node with the following:

connectionTimeout="20000"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42976r679454_chk'
  tag severity: 'medium'
  tag gid: 'V-239743'
  tag rid: 'SV-239743r679456_rule'
  tag stig_id: 'VCFL-67-000001'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-42935r679455_fix'
  tag satisfies: ['SRG-APP-000001-WSR-000001', 'SRG-APP-000435-WSR-000148']
  tag 'documentable'
  tag cci: ['CCI-000054', 'CCI-002385']
  tag nist: ['AC-10', 'SC-5 a']
end
