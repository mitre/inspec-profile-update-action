control 'SV-214246' do
  title 'The Apache web server must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to use, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.

'
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Search for the "Listen" directive:

# cat /<path_to_file>/httpd.conf | grep -i "Listen"

Verify that any enabled "Listen" directives specify both an IP address and port number.

If the "Listen" directive is found with only an IP address or only a port number specified, this is finding.

If the IP address is all zeros (i.e., 0.0.0.0:80 or [::ffff:0.0.0.0]:80), this is a finding.

If the "Listen" directive does not exist, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Set the "Listen" directive to listen on a specific IP address and port.

Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15460r276998_chk'
  tag severity: 'medium'
  tag gid: 'V-214246'
  tag rid: 'SV-214246r612240_rule'
  tag stig_id: 'AS24-U1-000360'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-15458r276999_fix'
  tag satisfies: ['SRG-APP-000142-WSR-000089', 'SRG-APP-000176-WSR-000096']
  tag 'documentable'
  tag legacy: ['SV-102749', 'V-92661']
  tag cci: ['CCI-000382', 'CCI-000186']
  tag nist: ['CM-7 b', 'IA-5 (2) (a) (1)']
end
