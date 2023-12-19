control 'SV-221287' do
  title 'OHS must have the WebLogicSSLVersion directive enabled to protect the integrity of remote sessions when integrated with WebLogic in accordance with the categorization of data hosted by the web server.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring end-to-end SSL:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WebLogicSSLVersion" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to "TLSv1.2", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WebLogicSSLVersion" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WebLogicSSLVersion" directive to "TLSv1_2", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23002r881044_chk'
  tag severity: 'medium'
  tag gid: 'V-221287'
  tag rid: 'SV-221287r881046_rule'
  tag stig_id: 'OH12-1X-000017'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-22991r881045_fix'
  tag 'documentable'
  tag legacy: ['SV-78643', 'V-64153']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
