control 'SV-214292' do
  title 'The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.'
  desc "The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end. 
 
Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the Apache web server's directory structure by locating directories without default pages. In the scenario, the Apache web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version."
  desc 'check', %q(View the "DocumentRoot" value by entering the following command: 
 
awk '{print $1,$2,$3}' <'INSTALL PATH'>/conf/httpd.conf|grep -i DocumentRoot|grep -v '^#' 
 
Note each location following the "DocumentRoot" string. This is the configured path(s) to the document root directory(s). 
 
To view a list of the directories and subdirectories and the file "index.html", from each stated "DocumentRoot" location enter the following commands: 
 
find . -type d 
find . -type f -name index.html 
 
Review the results for each document root directory and its subdirectories. 
 
If a directory does not contain an "index.html" or equivalent default document, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# apachectl -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Add a default document to the applicable directories.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15505r277217_chk'
  tag severity: 'medium'
  tag gid: 'V-214292'
  tag rid: 'SV-214292r881498_rule'
  tag stig_id: 'AS24-U2-000620'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-15503r881497_fix'
  tag 'documentable'
  tag legacy: ['SV-102891', 'V-92803']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
