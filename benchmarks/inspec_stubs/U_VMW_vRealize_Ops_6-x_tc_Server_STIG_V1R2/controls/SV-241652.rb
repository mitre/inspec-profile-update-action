control 'SV-241652' do
  title 'tc Server CaSa must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/server.xml.

Navigate to each of the <Connector> nodes.

If either the IP address or the port is not specified for each <Connector>, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to each of the <Connector> nodes.

Configure each <Connector> node with the correct port and address value:
address="XXXXX"
port="YYYYY"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44928r683816_chk'
  tag severity: 'medium'
  tag gid: 'V-241652'
  tag rid: 'SV-241652r879588_rule'
  tag stig_id: 'VROM-TC-000435'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-44887r683817_fix'
  tag 'documentable'
  tag legacy: ['SV-99589', 'V-88939']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
