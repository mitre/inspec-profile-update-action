control 'SV-214241' do
  title 'The Apache web server must not be a proxy server.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack, making the attack anonymous.'
  desc 'check', %q(If the server is a proxy server and not a web server, this check is Not Applicable.

In a command line, run "httpd -M | sort" to view a list of installed modules.

If any of the following modules are present, this is a finding:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the directive "ProxyRequest" in the "httpd.conf" file. 
If the ProxyRequest directive is set to “On”, this is a finding.)
  desc 'fix', %q(Determine where the proxy modules are located by running the following command:

grep -rl "proxy_module" <'INSTALL PATH'>

Edit the file and comment out the following modules:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module
Comment out the ProxyRequext directive in the httpd.conf file.

Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15455r881420_chk'
  tag severity: 'medium'
  tag gid: 'V-214241'
  tag rid: 'SV-214241r881421_rule'
  tag stig_id: 'AS24-U1-000260'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-15453r276984_fix'
  tag 'documentable'
  tag legacy: ['SV-102731', 'V-92643']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
