control 'SV-222975' do
  title 'ErrorReportValve showServerInfo must be set to false.'
  desc 'The Error Report Valve is a simple error handler for HTTP status codes that will generate and return HTML error pages. It can also be configured to return pre-defined static HTML pages for specific status codes and/or exception types. Disabling showServerInfo will only return the HTTP status code and remove all CSS from the default non-error related HTTP responses.'
  desc 'check', 'As an elevated user on the Tomcat server run the following command:

sudo grep -i ErrorReportValve $CATALINA_BASE/conf/server.xml file.

If the ErrorReportValve element is not defined and showServerInfo set to "false", this is a finding.

EXAMPLE:
<Host ...>
  ...
  <Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false"/>
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
showServerInfo="false" />
...
</Host>

Restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24647r426369_chk'
  tag severity: 'medium'
  tag gid: 'V-222975'
  tag rid: 'SV-222975r615938_rule'
  tag stig_id: 'TCAT-AS-000920'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-24636r426370_fix'
  tag 'documentable'
  tag legacy: ['SV-111473', 'V-102533']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
