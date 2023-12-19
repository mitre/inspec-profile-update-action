control 'SV-78743' do
  title 'OHS must not have the LanguagePriority directive enabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "LanguagePriority" directive.

2. Search for the "LanguagePriority" directive at the OHS server, virtual host, and directory configuration scopes.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "LanguagePriority" directive.

2. Search for the "LanguagePriority" directive at the OHS server, virtual host, and directory configuration scopes.

3. Comment out the "LanguagePriority" directive if it exists.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65005r1_chk'
  tag severity: 'low'
  tag gid: 'V-64253'
  tag rid: 'SV-78743r1_rule'
  tag stig_id: 'OH12-1X-000098'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-70183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
