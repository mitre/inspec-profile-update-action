control 'SV-221301' do
  title 'OHS must provide the capability to immediately disconnect or disable remote access to the hosted applications.'
  desc 'During an attack on the web server or any of the hosted applications, the system administrator may need to disconnect or disable access by users to stop the attack. 

The web server must provide a capability to disconnect users to a hosted application without compromising other hosted applications unless deemed necessary to stop the attack. Methods to disconnect or disable connections are to stop the application service for a specified hosted application, stop the web server, or block all connections through web server access list. 

The web server capabilities used to disconnect or disable users from connecting to hosted applications and the web server must be documented to make certain that, during an attack, the proper action is taken to conserve connectivity to any other hosted application if possible and to make certain log data is conserved for later forensic analysis.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>", "<Files>", or "<Location>" directive serving the application/content under attack at the OHS server, virtual host, or directory configuration scope.

3. If the "<Directory>", "<Files>", or "<Location>" directive serving the application/content under attack does not contain the appropriate "Order", "Deny", and "Allow" directives to prohibit access, this is a finding.'
  desc 'fix', %q(1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>", "<Files>", or "<Location>" directive serving the application/content under attack at the OHS server, virtual host, or directory configuration scope.

3. Set the "Order" directive to "allow,deny", add the directive if it does not exist.

4. Comment out any "Allow" directives to prohibit access to the application/content under attack if it exists.

5. Set "Deny" directives to "from all" to prohibit access to the application/content under attack, add the directive if it does not exist.

6. Issue a "nmSoftRestart(serverName='componentName',serverType='OHS') from the WLST shell prompt.)
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23016r414586_chk'
  tag severity: 'medium'
  tag gid: 'V-221301'
  tag rid: 'SV-221301r879693_rule'
  tag stig_id: 'OH12-1X-000034'
  tag gtitle: 'SRG-APP-000316-WSR-000170'
  tag fix_id: 'F-23005r414587_fix'
  tag 'documentable'
  tag legacy: ['SV-78991', 'V-64501']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
