control 'SV-221538' do
  title 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS, OHS must have the WLSProxySSL directive enabled to maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications. 

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring SSL termination at OHS:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "WLProxySSL" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "WLProxySSL" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23253r415293_chk'
  tag severity: 'medium'
  tag gid: 'V-221538'
  tag rid: 'SV-221538r879812_rule'
  tag stig_id: 'OH12-1X-000330'
  tag gtitle: 'SRG-APP-000441-WSR-000181'
  tag fix_id: 'F-23242r415294_fix'
  tag 'documentable'
  tag legacy: ['SV-79067', 'V-64577']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
