control 'SV-239652' do
  title 'The Security Token Service must limit the amount of time that each TCP connection is kept alive.'
  desc 'Denial of service (DoS) is one threat against web servers. Many DoS attacks attempt to consume web server resources in such a way that no more resources are available to satisfy legitimate requests. 

In Tomcat, the "connectionTimeout" attribute sets the number of milliseconds the server will wait after accepting a connection for the request URI line to be presented. This timeout will also be used when reading the request body (if any). This prevents idle sockets that are not sending HTTP requests from consuming system resources and potentially denying new connections.'
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-sso/vmware-sts/conf/server.xml | sed '2 s/xmlns=".*"//g' | xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@connectionTimeout' -

Expected result:

connectionTimeout="60000"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the value:

connectionTimeout="60000"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42885r679026_chk'
  tag severity: 'medium'
  tag gid: 'V-239652'
  tag rid: 'SV-239652r679028_rule'
  tag stig_id: 'VCST-67-000001'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-42844r679027_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
