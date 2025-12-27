control 'SV-221481' do
  title 'OHS must have the SSLCipherSuite directive enabled to perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', '1. As required, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', %q(1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. Set the "SSLCipherSuite" directive to "SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA,RSA_WITH_AES_128_CBC_SHA256,RSA_WITH_AES_256_CBC_SHA256,RSA_WITH_AES_128_GCM_SHA256,RSA_WITH_AES_256_GCM_SHA384,ECDHE_ECDSA_WITH_AES_128_CBC_SHA,ECDHE_ECDSA_WITH_AES_256_CBC_SHA,ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,ECDHE_RSA_WITH_AES_128_CBC_SHA,ECDHE_RSA_WITH_AES_256_CBC_SHA", add the directive if it does not exist.

Note: Ciphers may be removed from the list above per the organization's requirements or if vulnerabilities are found with a specific cipher.)
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23196r415126_chk'
  tag severity: 'medium'
  tag gid: 'V-221481'
  tag rid: 'SV-221481r879612_rule'
  tag stig_id: 'OH12-1X-000247'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-23185r415127_fix'
  tag 'documentable'
  tag legacy: ['SV-78911', 'V-64421']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
