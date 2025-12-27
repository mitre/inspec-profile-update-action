control 'SV-214279' do
  title 'The Apache web server must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'Apache web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 
 
Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 
 
Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes but is not limited to time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, and flow control rules invoked.'
  desc 'check', %q(In a command line, run "httpd -M | grep -i log_config_module".  
 
If the "log_config_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Search for the directive "LogFormat" in the httpd.conf file: 
 
# cat /<path_to_file>/httpd.conf | grep -i "LogFormat" 
 
If the "LogFormat" directive is missing or does not look like the following, this is a finding: 
 
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Uncomment the "log_config_module" module line. 
 
Configure the "LogFormat" in the "httpd.conf" file to look like the following: 
 
LogFormat "%a %A %h %H %l %m %s %t %u %U \"%{Referer}i\" " common 
 
Restart Apache: apachectl restart

NOTE: Your log format may be using different variables based on your environment, however  it should be verified to be producing the same end result of logged elements.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15492r277178_chk'
  tag severity: 'medium'
  tag gid: 'V-214279'
  tag rid: 'SV-214279r612241_rule'
  tag stig_id: 'AS24-U2-000090'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-15490r277179_fix'
  tag 'documentable'
  tag legacy: ['SV-102857', 'V-92769']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
