control 'SV-221513' do
  title 'OHS must have the LoadModule ossl_module directive enabled so SSL requests can be processed with client certificates only issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the file specified exists.  If the file does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. Set the "LoadModule ossl_module" directive to ""${PRODUCT_HOME}/modules/mod_ossl.so"", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23228r415218_chk'
  tag severity: 'medium'
  tag gid: 'V-221513'
  tag rid: 'SV-221513r415220_rule'
  tag stig_id: 'OH12-1X-000298'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-23217r415219_fix'
  tag 'documentable'
  tag legacy: ['SV-79007', 'V-64517']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
