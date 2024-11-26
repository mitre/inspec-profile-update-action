control 'SV-214284' do
  title 'Users and scripts running on behalf of users must be contained to the document root or home directory tree of the Apache web server.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm. 
 
The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files."
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Verify there is a single "Require" directive with the value of "all denied". 
 
Verify there are no "Allow" or "Deny" directives in the root <Directory> element. 
 
The following may be useful in extracting root directory elements from the Apache configuration for auditing: 
 
# perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' $APACHE_PREFIX/conf/httpd.conf  
 
If there are "Allow" or "Deny" directives in the root <Directory> element, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Set the root directory directive as follows: 
 
<Directory> 
... 
Require all denied 
... 
</Directory> 
 
Remove any "Deny" and "Allow" directives from the root <Directory> element. 
 
Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15497r277193_chk'
  tag severity: 'medium'
  tag gid: 'V-214284'
  tag rid: 'SV-214284r612241_rule'
  tag stig_id: 'AS24-U2-000350'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-15495r277194_fix'
  tag 'documentable'
  tag legacy: ['SV-102867', 'V-92779']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
