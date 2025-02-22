control 'SV-221288' do
  title 'OHS must have the WLProxySSL directive enabled to protect the integrity of remote sessions when integrated with WebLogic in accordance with the categorization of data hosted by the web server.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WLProxySSL" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23003r414547_chk'
  tag severity: 'medium'
  tag gid: 'V-221288'
  tag rid: 'SV-221288r879520_rule'
  tag stig_id: 'OH12-1X-000018'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-22992r414548_fix'
  tag 'documentable'
  tag legacy: ['SV-78645', 'V-64155']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
