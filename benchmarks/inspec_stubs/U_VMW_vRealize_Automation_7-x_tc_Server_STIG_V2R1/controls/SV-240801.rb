control 'SV-240801' do
  title 'tc Server VCAC must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address. 

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', 'Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

If either the IP address or the port is not specified for the <Connector>, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vcac/server.xml.

Navigate to the <Connector> node.

Configure the <Connector> node with the value 'address="XXXXX"'.

Note: Replace XXXXX with the appropriate address for that node.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44034r674145_chk'
  tag severity: 'medium'
  tag gid: 'V-240801'
  tag rid: 'SV-240801r674147_rule'
  tag stig_id: 'VRAU-TC-000430'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-43993r674146_fix'
  tag 'documentable'
  tag legacy: ['SV-100685', 'V-90035']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
