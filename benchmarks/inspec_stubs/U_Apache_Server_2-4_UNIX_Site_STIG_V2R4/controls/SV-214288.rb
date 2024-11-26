control 'SV-214288' do
  title 'Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.'
  desc 'Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol. 
 
When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.'
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "Header" directive:

# cat /<path_to_file>/httpd.conf | grep -i "Header"
 
If "HttpOnly" "secure" is not configured, this is a finding. 
 
"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure" 
 
Review the code. If, when creating cookies, the following is not occurring, this is a finding: 
 
function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; })
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add or configure the following line: 
 
"Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure" 
 
Add the "secure" attribute to the JavaScript set cookie in any application code: 
 
function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; }  

HttpOnly cannot be used since by definition this is a cookie set by JavaScript. 
 
Restart www_server and Apache.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15501r881491_chk'
  tag severity: 'medium'
  tag gid: 'V-214288'
  tag rid: 'SV-214288r881493_rule'
  tag stig_id: 'AS24-U2-000470'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-15499r881492_fix'
  tag 'documentable'
  tag legacy: ['SV-102883', 'V-92795']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
