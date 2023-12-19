control 'SV-78897' do
  title 'OHS must have the LoadModule ossl_module directive enabled to encrypt passwords during transmission.'
  desc 'Data used to authenticate, especially passwords, needs to be protected at all times, and encryption is the standard method for protecting authentication data during transmission. Data used to authenticate can be passed to and from the web server for many reasons. 

Examples include data passed from a user to the web server through an HTTPS connection for authentication, the web server authenticating to a backend database for data retrieval and posting, and the web server authenticating to a clustered web server manager for an update.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the file specified exists. If the file does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. Set the "LoadModule ossl_module" directive to ""${PRODUCT_HOME}/modules/mod_ossl.so"", add the directive if it does not exist.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65159r1_chk'
  tag severity: 'high'
  tag gid: 'V-64407'
  tag rid: 'SV-78897r1_rule'
  tag stig_id: 'OH12-1X-000240'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag fix_id: 'F-70337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
