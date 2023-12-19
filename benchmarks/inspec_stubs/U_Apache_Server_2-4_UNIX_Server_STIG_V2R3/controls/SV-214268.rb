control 'SV-214268' do
  title 'Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e., HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.

'
  desc 'check', %q(In a command line, run "httpd -M | grep -i session_cookie_module".

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Search for the directive "Session" in the "httpd.conf" file:

# cat /<path_to_file>/httpd.conf | grep -i "Session"
NOTE: SSL directives may also be located in /etc/httpd/conf.d/ssl.conf.

If the "Session" and "SessionCookieName" directives are not present, this is a finding.

If "Session" is not set to "on" and "SessionCookieName" does not contain "httpOnly" and "secure", this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"
 
NOTE: SSL directives may also be located in /etc/httpd/conf.d/ssl.conf.

Set "Session" to "on".

Ensure the "SessionCookieName" directive includes "httpOnly" and "secure".)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15482r803401_chk'
  tag severity: 'medium'
  tag gid: 'V-214268'
  tag rid: 'SV-214268r803403_rule'
  tag stig_id: 'AS24-U1-000870'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-15480r803402_fix'
  tag satisfies: ['SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag 'documentable'
  tag legacy: ['V-92741', 'SV-102829']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
