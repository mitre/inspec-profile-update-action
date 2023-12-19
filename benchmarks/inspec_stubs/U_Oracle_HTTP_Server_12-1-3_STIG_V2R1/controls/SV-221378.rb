control 'SV-221378' do
  title 'OHS must have the LoadModule authz_user_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.  This module provides authorization capabilities so authenticated users can be allowed or denied access to portions of the web site. This requirement is meant to disable an unneeded service; it is not intended to restrict the use of authorization when data access restrictions specify the use of authorization. Refer to the system security plan to determine if authorization is required based on data access requirements.'
  desc 'check', 'If the AO approved system security plan for web server configuration specifies using the OHS authz_user_module in order to meet application architecture requirements,  this requirement can be marked NA.

1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule authz_user_module" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule authz_user_module" directive at the OHS server configuration scope.

3. Comment out the "LoadModule authz_user_module" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23093r539626_chk'
  tag severity: 'medium'
  tag gid: 'V-221378'
  tag rid: 'SV-221378r539627_rule'
  tag stig_id: 'OH12-1X-000131'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23082r457166_fix'
  tag 'documentable'
  tag legacy: ['SV-78809', 'V-64319']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
