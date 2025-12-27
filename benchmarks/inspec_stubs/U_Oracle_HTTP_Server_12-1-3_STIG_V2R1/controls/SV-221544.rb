control 'SV-221544' do
  title 'If using the WebLogic Web Server Proxy Plugin and configuring end-to-end SSL, OHS must have the WLSSLWallet directive enabled to maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. 

The web server must utilize approved encryption when receiving transmitted data.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring end-to-end SSL:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLSSLWallet" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to a valid wallet folder, this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLSSLWallet" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WLSSLWallet" directive to the location (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the Oracle wallet created via orapki with AES Encryption (-compat_v12 parameters) that contains the certificate chain served by the WebLogic host/port combination, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23259r415311_chk'
  tag severity: 'medium'
  tag gid: 'V-221544'
  tag rid: 'SV-221544r415313_rule'
  tag stig_id: 'OH12-1X-000336'
  tag gtitle: 'SRG-APP-000442-WSR-000182'
  tag fix_id: 'F-23248r415312_fix'
  tag 'documentable'
  tag legacy: ['SV-79079', 'V-64589']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
