control 'SV-222942' do
  title 'The first line of request must be logged.'
  desc 'The access logfile format is defined within a Valve that implements the org.apache.catalina.valves.AccessLogValve interface within the /opt/tomcat/server.xml configuration file: The &quot;%r&quot; pattern code is included in the pattern element and logs the first line associated with the event, namely the request method, URL path, query string, and protocol ("&quot;" simply specifies a literal double quote). Including the pattern in the log configuration provides useful information about the time of the event which is critical for troubleshooting and forensic investigations.'
  desc 'check', 'As an elevated user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Review all "Valve" elements.

If the pattern= statement does not include &quot;%r&quot;, this is a finding.

EXAMPLE:
<Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="false">
...
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %t %u &quot;%r&quot; %s %b" />
  ...
</Host>'
  desc 'fix', 'As a privileged user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Modify the <Valve> element(s) nested within the <Host> element(s).

Change the AccessLogValve setting to include &quot;%r&quot; in the pattern= statement. 

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
  tag check_id: 'C-24614r426270_chk'
  tag severity: 'medium'
  tag gid: 'V-222942'
  tag rid: 'SV-222942r615938_rule'
  tag stig_id: 'TCAT-AS-000270'
  tag gtitle: 'SRG-APP-000097-AS-000060'
  tag fix_id: 'F-24603r426271_fix'
  tag 'documentable'
  tag legacy: ['SV-111413', 'V-102467']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
