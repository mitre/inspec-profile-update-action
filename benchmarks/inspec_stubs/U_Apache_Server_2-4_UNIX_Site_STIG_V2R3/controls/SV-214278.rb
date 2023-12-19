control 'SV-214278' do
  title 'The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.'
  desc 'The Apache web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, and communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented. 
 
Methods of communication are "http" for publicly displayed information, "https" to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.

'
  desc 'check', 'Verify the "ssl module" module is loaded
# httpd -M | grep -i ssl_module
Output:  ssl_module (shared)
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf

Search the ssl.conf file for the SSLProtocol
# cat /<path_to_file>/ssl.conf | grep -i "SSLProtocol" 
Output: SSLProtocol -ALL +TLSv1.2
 
If the "SSLProtocol" directive is missing or does not look like the following, this is a finding: 
 
SSLProtocol -ALL +TLSv1.2 
 
If the TLS version is not TLS 1.2 or higher, according to NIST SP 800-52 Rev 2, or if non-FIPS-approved algorithms are enabled, this is a finding. 
 
Note: In some cases, web servers are configured in an environment to support load balancing. This configuration most likely uses a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the websites may be installed on the content switch versus the individual websites. This solution is acceptable as long as the web servers are isolated from the general population LAN. Users should not have the ability to bypass the content switch to access the websites.'
  desc 'fix', 'Determine the location of the ssl.conf file:
# find / -name ssl.conf
Output: /etc/httpd/conf.d/ssl.conf
 
Ensure the "SSLProtocol" is added to ssl.conf and looks like the following: 
 
SSLProtocol -ALL +TLSv1.2 
 
Restart Apache: apachectl restart'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15491r881464_chk'
  tag severity: 'medium'
  tag gid: 'V-214278'
  tag rid: 'SV-214278r881466_rule'
  tag stig_id: 'AS24-U2-000030'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-15489r881465_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000015-WSR-000014', 'SRG-APP-000033-WSR-000169', 'SRG-APP-000172-WSR-000104', 'SRG-APP-000179-WSR-000110', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000206-WSR-000128', 'SRG-APP-000429-WSR-000113', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag 'documentable'
  tag legacy: ['SV-102851', 'V-92763']
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000213', 'CCI-000803', 'CCI-001166', 'CCI-001453', 'CCI-002448', 'CCI-002450', 'CCI-002452', 'CCI-002506']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'AC-3', 'IA-7', 'SC-18 (1)', 'AC-17 (2)', 'SC-12 (3)', 'SC-13 b', 'SC-15 (4)', 'SC-32']
end
