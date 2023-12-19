control 'SV-221281' do
  title 'OHS must have the LoadModule ossl_module directive enabled to protect the integrity of remote sessions in accordance with the categorization of data hosted by the web server.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the file specified exists.  If the file does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. Set the "LoadModule ossl_module" directive to""${PRODUCT_HOME}/modules/mod_ossl.so"", add the directive if it does not exist.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-22996r414526_chk'
  tag severity: 'high'
  tag gid: 'V-221281'
  tag rid: 'SV-221281r414528_rule'
  tag stig_id: 'OH12-1X-000011'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-22985r414527_fix'
  tag 'documentable'
  tag legacy: ['SV-78631', 'V-64141']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
