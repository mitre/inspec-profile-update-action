control 'SV-78719' do
  title 'OHS must have a log format defined to produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

Determining user accounts, processes running on behalf of the user, and running process identifiers also enable a better understanding of the overall event. User tool identification is also helpful to determine if events are related to overall user access or specific client tools.

Log record content that may be necessary to satisfy the requirement of this control includes: time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with a nickname of "dod" at the OHS server and virtual host configuration scopes.

3. Set the "LogFormat" directive to ""%h %l %u %t \\"%r\\" %>s %b \\"%{Referer}i\\" \\"%{User-Agent}i\\" ecid:%E xfor:%{X-Forwarded-For}i" dod", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64229'
  tag rid: 'SV-78719r1_rule'
  tag stig_id: 'OH12-1X-000069'
  tag gtitle: 'SRG-APP-000100-WSR-000064'
  tag fix_id: 'F-70159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
