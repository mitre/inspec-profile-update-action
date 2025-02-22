control 'SV-78809' do
  title 'OHS must have the LoadModule authz_user_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too insecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance. This requirement is meant to disable an unneeded service, it is not intended to restrict or limit the use of authorization when application requirements specify the need to use authorization functions. The authz_user_module in OHS provides authorization functionality so authenticated users can be allowed or denied access to portions of the web site.  Refer to the system security plan to determine if OHS based authorization functions are needed based on application or system data access requirements.'
  desc 'check', 'If the AO approved system security plan for web server configuration specifies using the OHS authz_user_module in order to meet application architecture requirements,  this requirement can be marked NA.

1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule authz_user_module" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule authz_user_module" directive at the OHS server configuration scope.

3. Comment out the "LoadModule authz_user_module" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65071r4_chk'
  tag severity: 'medium'
  tag gid: 'V-64319'
  tag rid: 'SV-78809r2_rule'
  tag stig_id: 'OH12-1X-000131'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-70249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
