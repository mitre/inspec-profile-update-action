control 'SV-221309' do
  title 'OHS must have a SSL log format defined to generate adequate logs by system startup and shutdown, system access, and system authentication events.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod_ssl" at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod_ssl" at the OHS server and virtual host configuration scopes.

3. Set the "LogFormat" directive to ""%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" ecid:%E xfor:%{X-Forwarded-For}i sslprot:%{SSL_PROTOCOL}x ciph:%{SSL_CIPHER}x" dod_ssl", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23024r414610_chk'
  tag severity: 'medium'
  tag gid: 'V-221309'
  tag rid: 'SV-221309r879559_rule'
  tag stig_id: 'OH12-1X-000046'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-23013r414611_fix'
  tag 'documentable'
  tag legacy: ['SV-78675', 'V-64185']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
