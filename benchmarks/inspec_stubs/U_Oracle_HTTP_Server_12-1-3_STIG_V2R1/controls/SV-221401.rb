control 'SV-221401' do
  title 'OHS must have the LoadModule proxy_balancer_module directive disabled.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended.  Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule proxy_balancer_module" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule proxy_balancer_module" directive at the OHS server configuration scope.

3. Comment out the "LoadModule proxy_balancer_module" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23116r414886_chk'
  tag severity: 'medium'
  tag gid: 'V-221401'
  tag rid: 'SV-221401r414888_rule'
  tag stig_id: 'OH12-1X-000154'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-23105r414887_fix'
  tag 'documentable'
  tag legacy: ['SV-78867', 'V-64377']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
