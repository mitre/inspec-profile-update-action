control 'SV-221369' do
  title 'OHS must have directives pertaining to certain scripting languages removed from virtual hosts.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "<FilesMatch "\\.(cgi|shtml|phtml|php)$">" directive at the virtual host configuration scope.

3. If the directive and any directives that it contains exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "<FilesMatch "\\.(cgi|shtml|phtml|php)$">" directive at the OHS server configuration scope.

3. Comment out the "<FilesMatch "\\.(cgi|shtml|phtml|php)$">" directive and any directives it contains if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23084r414790_chk'
  tag severity: 'medium'
  tag gid: 'V-221369'
  tag rid: 'SV-221369r414792_rule'
  tag stig_id: 'OH12-1X-000122'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23073r414791_fix'
  tag 'documentable'
  tag legacy: ['SV-78791', 'V-64301']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
