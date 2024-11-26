control 'SV-221490' do
  title 'OHS must have the LoadModule ossl_module directive enabled to meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules. 

The web server must provide FIPS-compliant encryption modules when authenticating users and processes.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the file specified exists. If the file does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule ossl_module" directive at the OHS server configuration scope.

3. Set the "LoadModule ossl_module" directive to ""${PRODUCT_HOME}/modules/mod_ossl.so"", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23205r415153_chk'
  tag severity: 'medium'
  tag gid: 'V-221490'
  tag rid: 'SV-221490r879616_rule'
  tag stig_id: 'OH12-1X-000257'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag fix_id: 'F-23194r415154_fix'
  tag 'documentable'
  tag legacy: ['SV-78929', 'V-64439']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
