control 'SV-79081' do
  title 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS, OHS must have the WLProxySSL directive enabled to maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Protecting the confidentiality and integrity of received information requires that application servers take measures to employ approved cryptography in order to protect the information during transmission over the network. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPsec tunnel. 

The web server must utilize approved encryption when receiving transmitted data.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WLProxySSL" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64591'
  tag rid: 'SV-79081r1_rule'
  tag stig_id: 'OH12-1X-000337'
  tag gtitle: 'SRG-APP-000442-WSR-000182'
  tag fix_id: 'F-70521r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
