control 'SV-79005' do
  title 'OHS must have the SSLCipherSuite directive enabled to implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting data that must be compartmentalized.'
  desc 'Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:
"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms are used to protect systems requiring the most stringent protection mechanisms."

Although persons may have a security clearance, they may not have a "need-to-know" and are required to be separated from the information in question. The web server must employ NSA-approved cryptography to protect classified information from those individuals who have no "need-to-know" or when encryption of compartmentalized data is required by data classification.'
  desc 'check', '1. As required, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', %q(1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. Set the "SSLCipherSuite" directive to "SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA,RSA_WITH_AES_128_CBC_SHA256,RSA_WITH_AES_256_CBC_SHA256,RSA_WITH_AES_128_GCM_SHA256,RSA_WITH_AES_256_GCM_SHA384,ECDHE_ECDSA_WITH_AES_128_CBC_SHA,ECDHE_ECDSA_WITH_AES_256_CBC_SHA,ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,ECDHE_RSA_WITH_AES_128_CBC_SHA,ECDHE_RSA_WITH_AES_256_CBC_SHA", add the directive if it does not exist.

Note:  Ciphers may be removed from the list above per the organization's requirements or if vulnerabilities are found with a specific cipher.)
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65267r1_chk'
  tag severity: 'high'
  tag gid: 'V-64515'
  tag rid: 'SV-79005r1_rule'
  tag stig_id: 'OH12-1X-000297'
  tag gtitle: 'SRG-APP-000416-WSR-000118'
  tag fix_id: 'F-70445r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
