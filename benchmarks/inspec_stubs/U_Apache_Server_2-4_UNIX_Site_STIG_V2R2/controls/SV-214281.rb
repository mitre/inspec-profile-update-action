control 'SV-214281' do
  title 'The Apache web server must have Multipurpose Internet Mail Extensions (MIME) that invoke operating system shell programs disabled.'
  desc "Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner. 
 
A MIME tells the web server what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type. 
 
A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of the web server."
  desc 'check', %q(In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
If "Action" or "AddHandler" exist and they configure .exe, .dll, .com, .bat, or .csh, or any other shell as a viewer for documents, this is a finding. 
 
If this is not documented and approved by the Information System Security Officer (ISSO), this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Disable MIME types for .exe, .dll, .com, .bat, and .csh programs. 
 
If "Action" or "AddHandler" exist and they configure any of the following (.exe, .dll, .com, .bat, or .csh), remove those references. 
 
Restart Apache: apachectl restart 
 
Ensure this process is documented and approved by the ISSO.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15494r277184_chk'
  tag severity: 'medium'
  tag gid: 'V-214281'
  tag rid: 'SV-214281r612241_rule'
  tag stig_id: 'AS24-U2-000300'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-15492r277185_fix'
  tag 'documentable'
  tag legacy: ['SV-102861', 'V-92773']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
