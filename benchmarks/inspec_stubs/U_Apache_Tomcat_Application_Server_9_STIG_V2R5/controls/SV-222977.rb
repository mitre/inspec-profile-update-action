control 'SV-222977' do
  title 'ErrorReportValve showReport must be set to false.'
  desc 'The Error Report Valve is a simple error handler for HTTP status codes that will generate and return HTML error pages. It can also be configured to return pre-defined static HTML pages for specific status codes and/or exception types. Disabling showReport will result in no error message or stack trace being send to the client. This setting can be tailored on a per-application basis within each application specific web.xml.'
  desc 'check', 'As an elevated user on the Tomcat server run the following command:

sudo grep -i ErrorReportValve $CATALINA_BASE/conf/server.xml file.

If the ErrorReportValve element is not defined and showReport set to "false", this is a finding.

EXAMPLE:
<Host ...>
  ...
  <Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false"/>
  ...
</Host>'
  desc 'fix', 'As a privileged user on the Tomcat server:

Edit the $CATALINA_BASE/conf/server.xml file.

Create or modify an ErrorReportValve <Valve> element nested beneath each <Host> element.

EXAMPLE:
<Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="false">
...
<Valve className="org.apache.catalina.valves.ErrorReportValve" 
showReport="false" />

</Host>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24649r426375_chk'
  tag severity: 'medium'
  tag gid: 'V-222977'
  tag rid: 'SV-222977r879656_rule'
  tag stig_id: 'TCAT-AS-000940'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag fix_id: 'F-24638r426376_fix'
  tag 'documentable'
  tag legacy: ['SV-111477', 'V-102537']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
