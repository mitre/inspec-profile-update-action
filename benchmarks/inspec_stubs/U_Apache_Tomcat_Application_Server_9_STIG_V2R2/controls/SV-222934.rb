control 'SV-222934' do
  title 'DefaultServlet must be set to readonly for PUT and DELETE.'
  desc 'The DefaultServlet is a servlet provided with Tomcat. It is called when no other suitable page can be displayed to the client. The DefaultServlet serves static resources as well as directory listings and is declared globally in $CATALINA_BASE/conf/web.xml. By default, Tomcat behaves as if the DefaultServlet is set to "true" (HTTP commands like PUT and DELETE are rejected). However, the readonly parameter is not in the web.xml file by default so to ensure proper configuration and system operation, the "readonly" parameter in web.xml  must be created and set to "true". Creating the setting in web.xml provides assurances the system is operating as required. Changing the readonly parameter to false could allow clients to delete or modify static resources on the server and upload new resources.'
  desc 'check', 'From the Tomcat server run the following command:

sudo cat $CATALINA_BASE/conf/web.xml |grep -i -A5 -B2 defaultservlet 

If the "readonly" param-value for the "DefaultServlet" servlet class = "false" or does not exist, this is a finding.'
  desc 'fix', 'From the Tomcat server console as a privileged user:

Edit the $CATALINA_BASE/conf/web.xml file. 

If the "readonly" param-value does not exist, it must be created.

Ensure the "readonly" param-value for the "DefaultServlet" servlet class = "true".'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24606r612228_chk'
  tag severity: 'medium'
  tag gid: 'V-222934'
  tag rid: 'SV-222934r615938_rule'
  tag stig_id: 'TCAT-AS-000090'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag fix_id: 'F-24595r612229_fix'
  tag 'documentable'
  tag legacy: ['SV-111399', 'V-102451']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
