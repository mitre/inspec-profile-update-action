control 'SV-239372' do
  title 'ESX Agent Manager must limit the amount of time that each TCP connection is kept alive.'
  desc 'Denial of service is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests. 

In Tomcat, the "connectionTimeout" attribute sets the number of milliseconds the server will wait after accepting a connection for the request URI line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.'
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --xpath '/Server/Service/Connector/@connectionTimeout' /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

connectionTimeout="20000"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Configure the <Connector> node with the value:

connectionTimeout="20000"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 EAM Tomcat'
  tag check_id: 'C-42605r674608_chk'
  tag severity: 'medium'
  tag gid: 'V-239372'
  tag rid: 'SV-239372r674610_rule'
  tag stig_id: 'VCEM-67-000001'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-42564r674609_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
