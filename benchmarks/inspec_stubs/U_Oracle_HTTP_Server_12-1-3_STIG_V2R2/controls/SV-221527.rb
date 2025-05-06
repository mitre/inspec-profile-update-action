control 'SV-221527' do
  title 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS, OHS must have the WLProxySSL directive enabled to prevent unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WLProxySSL" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23242r415260_chk'
  tag severity: 'medium'
  tag gid: 'V-221527'
  tag rid: 'SV-221527r879810_rule'
  tag stig_id: 'OH12-1X-000315'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-23231r415261_fix'
  tag 'documentable'
  tag legacy: ['SV-79045', 'V-64555']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
