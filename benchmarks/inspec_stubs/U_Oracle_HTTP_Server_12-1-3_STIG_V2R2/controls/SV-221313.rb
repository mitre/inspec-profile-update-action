control 'SV-221313' do
  title 'OHS must have a log format defined for log records generated to capture sufficient information to establish what type of events occurred.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. Set the "LogFormat" directive to ""%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" ecid:%E xfor:%{X-Forwarded-For}i" dod", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23028r414622_chk'
  tag severity: 'medium'
  tag gid: 'V-221313'
  tag rid: 'SV-221313r879563_rule'
  tag stig_id: 'OH12-1X-000051'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-23017r414623_fix'
  tag 'documentable'
  tag legacy: ['SV-78683', 'V-64193']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
