control 'SV-222938' do
  title 'AccessLogValve must be configured per each virtual host.'
  desc 'Application servers utilize role-based access controls in order to specify the individuals who are allowed to configure application component loggable events. The application server must be configured to select which personnel are assigned the role of selecting which loggable events are to be logged.

'
  desc 'check', 'As an elevated user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Review for all <Host> elements.

If a <Valve className="org.apache.catalina.valves.AccessLogValve" .../> element is not nested within each <Host> element, this is a finding.

EXAMPLE:
<Host name="localhost" appBase="webapps"
 unpackWARs="true" autoDeploy="false">
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
 prefix="localhost_access_log" suffix=".txt"
 pattern="%h %l %t %u &quot;%r&quot; %s %b" />
 ...
</Host>'
  desc 'fix', 'As a privileged user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Create a <Valve> element that is nested beneath the <Host> element containing an AccessLogValve.

EXAMPLE:
<Host name="localhost" appBase="webapps"
 unpackWARs="true" autoDeploy="false">
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
 prefix="localhost_access_log" suffix=".txt"
 pattern="%h %l %t %u &quot;%r&quot; %s %b" />
 ...
</Host>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24610r426258_chk'
  tag severity: 'medium'
  tag gid: 'V-222938'
  tag rid: 'SV-222938r879560_rule'
  tag stig_id: 'TCAT-AS-000180'
  tag gtitle: 'SRG-APP-000090-AS-000051'
  tag fix_id: 'F-24599r426259_fix'
  tag satisfies: ['SRG-APP-000090-AS-000051', 'SRG-APP-000095-AS-000056', 'SRG-APP-000100-AS-000063', 'SRG-APP-000101-AS-000072', 'SRG-APP-000503-AS-000228', 'SRG-APP-000505-AS-000230', 'SRG-APP-000506-AS-000231']
  tag 'documentable'
  tag legacy: ['SV-111549', 'V-102603']
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000171', 'CCI-000172', 'CCI-001487']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 b', 'AU-12 c', 'AU-3 f']
end
