control 'SV-221286' do
  title 'OHS must have the WLSSLWallet directive enabled to protect the integrity of remote sessions when integrated with WebLogic in accordance with the categorization of data hosted by the web server.'
  desc 'Data exchanged between the user and the web server can range from static display data to credentials used to log into the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring end-to-end SSL:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLSSLWallet" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to a folder containing a valid wallet, this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLSSLWallet" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WLSSLWallet" directive to the location (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the Oracle wallet created via orapki with AES Encryption (-compat_v12 parameters) that contains the certificate chain served by the WebLogic host/port combination, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23001r414541_chk'
  tag severity: 'medium'
  tag gid: 'V-221286'
  tag rid: 'SV-221286r414543_rule'
  tag stig_id: 'OH12-1X-000016'
  tag gtitle: 'SRG-APP-000015-WSR-000014'
  tag fix_id: 'F-22990r414542_fix'
  tag 'documentable'
  tag legacy: ['SV-78641', 'V-64151']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
