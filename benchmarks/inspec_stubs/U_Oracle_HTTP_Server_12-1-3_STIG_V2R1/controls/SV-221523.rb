control 'SV-221523' do
  title 'OHS must have the SSLCipherSuite directive enabled to prevent unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.'
  desc 'check', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', %q(1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. Set the "SSLCipherSuite" directive to "SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA,RSA_WITH_AES_128_CBC_SHA256,RSA_WITH_AES_256_CBC_SHA256,RSA_WITH_AES_128_GCM_SHA256,RSA_WITH_AES_256_GCM_SHA384,ECDHE_ECDSA_WITH_AES_128_CBC_SHA,ECDHE_ECDSA_WITH_AES_256_CBC_SHA,ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,ECDHE_RSA_WITH_AES_128_CBC_SHA,ECDHE_RSA_WITH_AES_256_CBC_SHA", add the directive if it does not exist.

Note: Ciphers may be removed from the list above per the organization's requirements or if vulnerabilities are found with a specific cipher.)
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23238r415248_chk'
  tag severity: 'high'
  tag gid: 'V-221523'
  tag rid: 'SV-221523r415250_rule'
  tag stig_id: 'OH12-1X-000311'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-23227r415249_fix'
  tag 'documentable'
  tag legacy: ['SV-79037', 'V-64547']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
