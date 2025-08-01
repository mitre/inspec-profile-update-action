control 'SV-214278' do
  title 'The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.'
  desc 'The Apache web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, and communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented. 
 
Methods of communication are "http" for publicly displayed information, "https" to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.

'
  desc 'check', %q(In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf" 
 
Search for the directive "SSLProtocol" in the "httpd.conf" file: 
 
# cat /<path_to_file>/httpd.conf | grep -i "SSLProtocol" 
 
If the "SSLProtocol" directive is missing or does not look like the following, this is a finding: 
 
SSLProtocol -ALL +TLSv1.2 
 
If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52 Rev 2, or if non-FIPS-approved algorithms are enabled, this is a finding. 
 
NOTE: In some cases, web servers are configured in an environment to support load balancing. This configuration most likely uses a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the websites may be installed on the content switch versus the individual websites. This solution is acceptable as long as the web servers are isolated from the general population LAN. Users should not have the ability to bypass the content switch to access the websites.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
-D SERVER_CONFIG_FILE="conf/httpd.conf"  
 
Ensure the "SSLProtocol" is added and looks like the following: 
 
SSLProtocol -ALL +TLSv1.2 
 
Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15491r277175_chk'
  tag severity: 'medium'
  tag gid: 'V-214278'
  tag rid: 'SV-214278r612241_rule'
  tag stig_id: 'AS24-U2-000030'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-15489r277176_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000015-WSR-000014', 'SRG-APP-000033-WSR-000169', 'SRG-APP-000172-WSR-000104', 'SRG-APP-000179-WSR-000110', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000206-WSR-000128', 'SRG-APP-000429-WSR-000113', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag 'documentable'
  tag legacy: ['SV-102851', 'V-92763']
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000213', 'CCI-000803', 'CCI-001166', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422', 'CCI-002476']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'AC-3', 'IA-7', 'SC-18 (1)', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (2)', 'SC-28 (1)']
end
