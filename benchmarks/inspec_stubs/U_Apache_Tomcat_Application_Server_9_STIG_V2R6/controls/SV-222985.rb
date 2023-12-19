control 'SV-222985' do
  title 'Application user name must be logged.'
  desc 'The access logfile format is defined within a Valve that implements the org.apache.catalina.valves.AccessLogValve interface within the /opt/tomcat/server.xml configuration file: The %u pattern code is included in the pattern element and logs the username used to authenticate to an application. Including the username pattern in the log configuration provides useful information about the application user who is logging in, which is critical for troubleshooting and forensic investigations.'
  desc 'check', 'As an elevated user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Review all "Valve" elements.

If the pattern= statement does not include %u, this is a finding.

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

Modify the <Valve> element that is nested beneath the <Host> element. Change the AccessLogValve setting to include %u in the pattern= statement.

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
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24657r426399_chk'
  tag severity: 'low'
  tag gid: 'V-222985'
  tag rid: 'SV-222985r879720_rule'
  tag stig_id: 'TCAT-AS-001080'
  tag gtitle: 'SRG-APP-000343-AS-000030'
  tag fix_id: 'F-24646r426400_fix'
  tag 'documentable'
  tag legacy: ['SV-111493', 'V-102553']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
