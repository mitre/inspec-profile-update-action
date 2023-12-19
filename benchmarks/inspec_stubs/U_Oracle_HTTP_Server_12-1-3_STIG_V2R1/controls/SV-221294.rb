control 'SV-221294' do
  title 'OHS must have a log format defined to generate adequate information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. Set the "LogFormat" directive to ""%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" ecid:%E xfor:%{X-Forwarded-For}i" dod", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23009r414565_chk'
  tag severity: 'medium'
  tag gid: 'V-221294'
  tag rid: 'SV-221294r414567_rule'
  tag stig_id: 'OH12-1X-000024'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-22998r414566_fix'
  tag 'documentable'
  tag legacy: ['SV-78657', 'V-64167']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
