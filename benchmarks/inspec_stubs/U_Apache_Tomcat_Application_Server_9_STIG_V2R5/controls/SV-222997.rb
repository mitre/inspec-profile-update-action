control 'SV-222997' do
  title 'AccessLogValve must be configured for Catalina engine.'
  desc '<0> [object Object]'
  desc 'check', 'As an elevated user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Review the <Engine> element. Ensure one AccessLog <Valve> element is nested within the Engine element. 

If a <Valve className="org.apache.catalina.valves.AccessLogValve" .../> element is not defined, this is a finding.

EXAMPLE:
<Engine name="Standalone" ...>
  ...
  <Valve className="org.apache.catalina.valves.AccessLogValve"
         prefix="catalina_access_log" suffix=".txt"
         pattern="common"/>
  ...
</Engine>'
  desc 'fix', 'As a privileged user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Create a <Valve> element that is nested beneath the <Host> element containing an AccessLogValve. 

EXAMPLE:
<Host name="localhost"  appBase="webapps"
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
  tag check_id: 'C-24669r426435_chk'
  tag severity: 'medium'
  tag gid: 'V-222997'
  tag rid: 'SV-222997r879866_rule'
  tag stig_id: 'TCAT-AS-001560'
  tag gtitle: 'SRG-APP-000495-AS-000220'
  tag fix_id: 'F-24658r426436_fix'
  tag legacy: ['SV-111517', 'V-102577']
  tag cci: ['CCI-000172', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1)']
end
