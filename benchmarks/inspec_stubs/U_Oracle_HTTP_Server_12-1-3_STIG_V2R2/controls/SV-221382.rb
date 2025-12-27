control 'SV-221382' do
  title 'OHS must have the LoadModule proxy_http_module directive disabled.'
  desc 'A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system. 

The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance. The proxy_http_module requires the service of mod_proxy. It provides the features used for proxying HTTP and HTTPS requests. If proxy services are required, the proxy configuration must be approved by the AO.'
  desc 'check', 'If the AO approved system security plan for the web server configuration specifies using the proxy_http_module directive in order to meet application architecture requirements and authentication is enforced, this requirement is NA.

1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule proxy_http_module" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule proxy_http_module" directive at the OHS server configuration scope.

3. Comment out the "LoadModule proxy_http_module" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23097r539628_chk'
  tag severity: 'medium'
  tag gid: 'V-221382'
  tag rid: 'SV-221382r879587_rule'
  tag stig_id: 'OH12-1X-000135'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-23086r457157_fix'
  tag 'documentable'
  tag legacy: ['SV-78817', 'V-64327']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
