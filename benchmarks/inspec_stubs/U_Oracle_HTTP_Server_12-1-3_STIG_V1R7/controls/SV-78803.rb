control 'SV-78803' do
  title 'OHS must have the AliasMatch directive pertaining to the OHS manuals disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "AliasMatch ^/manual(?:/(?:de|en|es|fr|ja|ko|pt-br|ru|tr))?(/.*)?$ "${PRODUCT_HOME}/manual$1"" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for an "AliasMatch ^/manual(?:/(?:de|en|es|fr|ja|ko|pt-br|ru|tr))?(/.*)?$ "${PRODUCT_HOME}/manual$1"" directive at the OHS server configuration scope.

3. Comment out the "AliasMatch ^/manual(?:/(?:de|en|es|fr|ja|ko|pt-br|ru|tr))?(/.*)?$ "${PRODUCT_HOME}/manual$1"" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64313'
  tag rid: 'SV-78803r1_rule'
  tag stig_id: 'OH12-1X-000128'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-70243r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
