control 'SV-221536' do
  title 'If using the WebLogic Web Server Proxy Plugin and configuring end-to-end SSL, OHS must have the SecureProxy directive enabled to maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications. 

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', 'If using the WebLogic Web Server Proxy Plugin and configuring end-to-end SSL:

1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SecureProxy" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that contains an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SecureProxy" directive within an "<IfModule weblogic_module>" at the virtual host configuration scope.

3. Set the "SecureProxy" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23251r415287_chk'
  tag severity: 'medium'
  tag gid: 'V-221536'
  tag rid: 'SV-221536r879812_rule'
  tag stig_id: 'OH12-1X-000328'
  tag gtitle: 'SRG-APP-000441-WSR-000181'
  tag fix_id: 'F-23240r415288_fix'
  tag 'documentable'
  tag legacy: ['SV-79063', 'V-64573']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
