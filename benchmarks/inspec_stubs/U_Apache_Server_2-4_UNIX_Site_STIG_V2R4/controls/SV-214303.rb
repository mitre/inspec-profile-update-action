control 'SV-214303' do
  title 'Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.'
  desc 'Cookies can be sent to a client using TLS/SSL to encrypt the cookies, but TLS/SSL is not used by every hosted application since the data being displayed does not require the encryption of the transmission. To safeguard against cookies, especially session cookies, being sent in plaintext, a cookie can be encrypted before transmission. To force a cookie to be encrypted before transmission, the cookie "Secure" property can be set.'
  desc 'check', %q(In a command line, run "httpd -M | grep -i session_cookie_module". 
 
If "session_cookie_module" is not listed, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions "apache2ctl -V" or  "httpd -V" can also be used. 

Search for the "Session" and "SessionCookieName" directives:

# cat /<path_to_file>/httpd.conf | grep -i "Session"
# cat /<path_to_file>/httpd.conf | grep -i "SessionCookieName"

If "Session" is not "on" and "SessionCookieName" does not contain "httpOnly" and "secure", this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set "Session" to "on". 
 
Ensure the "SessionCookieName" directive includes "httpOnly" and "secure".)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15516r881519_chk'
  tag severity: 'medium'
  tag gid: 'V-214303'
  tag rid: 'SV-214303r881521_rule'
  tag stig_id: 'AS24-U2-000890'
  tag gtitle: 'SRG-APP-000439-WSR-000155'
  tag fix_id: 'F-15514r881520_fix'
  tag 'documentable'
  tag legacy: ['SV-102923', 'V-92835']
  tag cci: ['CCI-002448']
  tag nist: ['SC-12 (3)']
end
