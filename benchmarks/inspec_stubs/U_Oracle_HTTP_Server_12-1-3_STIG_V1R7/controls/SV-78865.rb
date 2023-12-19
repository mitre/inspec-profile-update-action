control 'SV-78865' do
  title 'OHS must have the LoadModule proxy_connect_module directive disabled.'
  desc 'A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended.  Scanning for web servers that will also proxy requests into an otherwise protected network is a very common attack making the attack anonymous.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule proxy_connect_module" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule proxy_connect_module" directive at the OHS server configuration scope.

3. Comment out the "LoadModule proxy_connnect_module" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65127r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64375'
  tag rid: 'SV-78865r1_rule'
  tag stig_id: 'OH12-1X-000153'
  tag gtitle: 'SRG-APP-000141-WSR-000076'
  tag fix_id: 'F-70305r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
