control 'SV-221493' do
  title 'OHS must have the SSLCipherSuite directive enabled to meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules. 

The web server must provide FIPS-compliant encryption modules when authenticating users and processes.'
  desc 'check', '1. As required, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', %q(1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. Set the "SSLCipherSuite" directive to "SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA,RSA_WITH_AES_128_CBC_SHA256,RSA_WITH_AES_256_CBC_SHA256,RSA_WITH_AES_128_GCM_SHA256,RSA_WITH_AES_256_GCM_SHA384,ECDHE_ECDSA_WITH_AES_128_CBC_SHA,ECDHE_ECDSA_WITH_AES_256_CBC_SHA,ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,ECDHE_RSA_WITH_AES_128_CBC_SHA,ECDHE_RSA_WITH_AES_256_CBC_SHA", add the directive if it does not exist.

Note: Ciphers may be removed from the list above per the organization's requirements or if vulnerabilities are found with a specific cipher.)
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23208r415162_chk'
  tag severity: 'medium'
  tag gid: 'V-221493'
  tag rid: 'SV-221493r879616_rule'
  tag stig_id: 'OH12-1X-000260'
  tag gtitle: 'SRG-APP-000179-WSR-000111'
  tag fix_id: 'F-23197r415163_fix'
  tag 'documentable'
  tag legacy: ['SV-78935', 'V-64445']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
