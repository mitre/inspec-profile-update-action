control 'SV-221319' do
  title 'OHS must have a log format defined for log records that allow the establishment of where within OHS the events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct location or process within the web server where the events occurred is important during forensic analysis. Correctly determining the web service, plug-in, or module will add information to the overall reconstruction of the logged event. For example, an event that occurred during communication to a cgi module might be handled differently than an event that occurred during a communication session to a user.

Without sufficient information establishing where the log event occurred within the web server, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. Set the "LogFormat" directive to ""%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" ecid:%E xfor:%{X-Forwarded-For}i" dod", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23034r414640_chk'
  tag severity: 'medium'
  tag gid: 'V-221319'
  tag rid: 'SV-221319r879565_rule'
  tag stig_id: 'OH12-1X-000057'
  tag gtitle: 'SRG-APP-000097-WSR-000058'
  tag fix_id: 'F-23023r414641_fix'
  tag 'documentable'
  tag legacy: ['SV-78695', 'V-64205']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
