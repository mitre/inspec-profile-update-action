control 'SV-221326' do
  title 'OHS, behind a load balancer or proxy server, must have the SSL log format set correctly to produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every logable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod_ssl" at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod_ssl" at the OHS server and virtual host configuration scopes.

3. Set the "LogFormat" directive to ""%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" ecid:%E xfor:%{X-Forwarded-For}i sslprot:%{SSL_PROTOCOL}x ciph:%{SSL_CIPHER}x" dod_ssl", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23041r414661_chk'
  tag severity: 'medium'
  tag gid: 'V-221326'
  tag rid: 'SV-221326r879566_rule'
  tag stig_id: 'OH12-1X-000064'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-23030r414662_fix'
  tag 'documentable'
  tag legacy: ['SV-78709', 'V-64219']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
