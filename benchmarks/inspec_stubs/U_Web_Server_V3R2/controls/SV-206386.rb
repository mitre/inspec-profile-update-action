control 'SV-206386' do
  title 'The web server must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.  If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.  

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', 'Review the web server documentation and deployment configuration to determine whether the web server is configured to listen on a specified IP address and port.

Request a client user try to access the web server on any other available IP addresses on the hosting hardware.

If an IP address is not configured on the web server or a client can reach the web server on other IP addresses assigned to the hosting hardware, this is a finding.'
  desc 'fix', 'Configure the web server to only listen on a specified IP address and port.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6647r377750_chk'
  tag severity: 'medium'
  tag gid: 'V-206386'
  tag rid: 'SV-206386r879588_rule'
  tag stig_id: 'SRG-APP-000142-WSR-000089'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-6647r377751_fix'
  tag 'documentable'
  tag legacy: ['SV-54283', 'V-41706']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
