control 'SV-221535' do
  title 'OHS must have the SSLCipherSuite directive enabled to maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications. 

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', %q(1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLCipherSuite" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. Set the "SSLCipherSuite" directive to "SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA,RSA_WITH_AES_128_CBC_SHA256,RSA_WITH_AES_256_CBC_SHA256,RSA_WITH_AES_128_GCM_SHA256,RSA_WITH_AES_256_GCM_SHA384,ECDHE_ECDSA_WITH_AES_128_CBC_SHA,ECDHE_ECDSA_WITH_AES_256_CBC_SHA,ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,ECDHE_RSA_WITH_AES_128_CBC_SHA,ECDHE_RSA_WITH_AES_256_CBC_SHA", add the directive if it does not exist.

Note: Ciphers may be removed from the list above per the organization's requirements or if vulnerabilities are found with a specific cipher.)
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23250r415284_chk'
  tag severity: 'medium'
  tag gid: 'V-221535'
  tag rid: 'SV-221535r879812_rule'
  tag stig_id: 'OH12-1X-000327'
  tag gtitle: 'SRG-APP-000441-WSR-000181'
  tag fix_id: 'F-23239r415285_fix'
  tag 'documentable'
  tag legacy: ['SV-79061', 'V-64571']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
