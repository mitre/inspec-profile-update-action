control 'SV-214293' do
  title 'Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in an Apache web server includes any information about the Apache web server, backend systems being accessed, and plug-ins or modules being used. 
 
Apache web servers will often display error messages to client users, displaying enough information to aid in the debugging of the error. The information given back in error messages may display the Apache web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 
 
This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the Apache web server.'
  desc 'check', %q(In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
If the "ErrorDocument" directive is not being used, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Use the "ErrorDocument" directive to enable custom error pages. 
 
ErrorDocument 500 "Sorry, our script crashed. Oh dear" 
ErrorDocument 500 /cgi-bin/crash-recover 
ErrorDocument 500 http://error.example.com/server_error.html 
ErrorDocument 404 /errors/not_found.html 
ErrorDocument 401 /subscription/how_to_subscribe.html 
 
The syntax of the ErrorDocument directive is: 
 
ErrorDocument <3-digit-code> <action> 
 
Additional Information: 

https://httpd.apache.org/docs/2.4/custom-error.html)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15506r277220_chk'
  tag severity: 'medium'
  tag gid: 'V-214293'
  tag rid: 'SV-214293r612241_rule'
  tag stig_id: 'AS24-U2-000630'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-15504r277221_fix'
  tag 'documentable'
  tag legacy: ['SV-102893', 'V-92805']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
