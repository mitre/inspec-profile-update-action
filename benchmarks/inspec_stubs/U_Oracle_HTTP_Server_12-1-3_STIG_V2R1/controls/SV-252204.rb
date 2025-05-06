control 'SV-252204' do
  title 'OHS must capture, record, and log all content related to a user session.'
  desc 'A user session to a web server is in the context of a user accessing a hosted application that extends to any plug-ins/modules and services that may execute on behalf of the user.

The web server must be capable of enabling a setting for troubleshooting, debugging, or forensic gathering purposes which will log all user session information related to the hosted application session. Without the capability to capture, record, and log all content related to a user session, investigations into suspicious user activity would be hampered.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with nicknames of "dod" and "dod_ssl" at the OHS server and virtual host configuration scopes.

3. If either of these directives is omitted or set improperly, this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "LogFormat" directive with nicknames of "dod" and "dod_ssl" at the OHS server and virtual host configuration scopes.

3a. If the session id is contained within a cookie, modify the "LogFormat" directive with nicknames of "dod" and "dod_ssl" to include "sess:%{JSESSIONID}C", add the directive if it does not exist unless inherited from a larger scope.
3b. If the session id is contained within a header variable, modify the "LogFormat" directives with nicknames of "dod" and "dod_ssl" to include "sess:%{X-JSESSIONID}o" dod", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-55660r816502_chk'
  tag severity: 'medium'
  tag gid: 'V-252204'
  tag rid: 'SV-252204r816508_rule'
  tag stig_id: 'OH12-1X-000049'
  tag gtitle: 'SRG-APP-000516-WSR-000079'
  tag fix_id: 'F-55610r816503_fix'
  tag 'documentable'
  tag legacy: ['SV-77643', 'V-63153']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
