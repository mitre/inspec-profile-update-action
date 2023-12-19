control 'SV-214285' do
  title 'The Apache web server must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to use, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address. 
 
Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 
 
Verify that for each "VirtualHost" directive, there is an IP address and port. 
 
If there is not, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set each "VirtualHost" directive to listen to on a specific IP address and port.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15498r881482_chk'
  tag severity: 'medium'
  tag gid: 'V-214285'
  tag rid: 'SV-214285r881484_rule'
  tag stig_id: 'AS24-U2-000360'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-15496r881483_fix'
  tag 'documentable'
  tag legacy: ['SV-102869', 'V-92781']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
