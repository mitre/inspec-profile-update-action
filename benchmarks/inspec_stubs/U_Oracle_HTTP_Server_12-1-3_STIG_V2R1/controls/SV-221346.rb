control 'SV-221346' do
  title 'OHS must not have the ForceLanguagePriority directive enabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "ForceLanguagePriority" directive.

2. Search for the "ForceLanguagePriority" directive at the OHS server, virtual host, and directory configuration scopes.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "ForceLanguagePriority" directive.

2. Search for the "ForceLanguagePriority" directive at the OHS server, virtual host, and directory configuration scopes.

3. Comment out the "ForceLanguagePriority" directive if it exists.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23061r414721_chk'
  tag severity: 'low'
  tag gid: 'V-221346'
  tag rid: 'SV-221346r414723_rule'
  tag stig_id: 'OH12-1X-000099'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23050r414722_fix'
  tag 'documentable'
  tag legacy: ['SV-78745', 'V-64255']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
