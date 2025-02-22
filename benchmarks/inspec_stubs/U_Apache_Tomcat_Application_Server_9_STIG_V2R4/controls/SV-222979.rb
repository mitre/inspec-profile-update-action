control 'SV-222979' do
  title 'Idle timeout for management application must be set to 10 minutes.'
  desc "Tomcat can set idle session timeouts on a per application basis. The management application is provided with the Tomcat installation and is used to manage the applications that are installed on the Tomcat Server. Setting the idle timeout for the management application will kill the admin user's session after 10 minutes of inactivity. This will limit the opportunity for unauthorized persons to hijack the admin session. This setting will also affect the default timeout behavior of all hosted web applications. To adjust the individual hosted application settings that are not related to management of the system, modify the individual application web.xml file if application timeout requirements differ from the STIG. "
  desc 'check', 'If the manager application has been deleted from the system, this is not a finding. 

From the Tomcat server as a privileged user, run the following commands:

sudo grep -i session-timeout $CATALINA_BASE/webapps/manager/META-INF/web.xml 

sudo grep -i session-timeout 
$CATALINA_BASE/conf/web.xml

If the session-timeout setting is not configured to be 10 minutes in at least one of these files, this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user:

To affect session timeout for all applications including the management application, edit the:
$CATALINA_BASE/conf/web.xml file.

To affect session timeout for the management application only, edit the:
$CATALINA_BASE/webapps/manager/META-INF/web.xml file. 

Locate the session-timeout setting located within the session-config element.

Modify the session-timeout setting to be 10 minutes.

Save the file.

sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24651r426381_chk'
  tag severity: 'medium'
  tag gid: 'V-222979'
  tag rid: 'SV-222979r615938_rule'
  tag stig_id: 'TCAT-AS-000970'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-24640r622488_fix'
  tag satisfies: ['SRG-APP-000389', 'SRG-APP-000220']
  tag 'documentable'
  tag legacy: ['SV-111481', 'V-102541']
  tag cci: ['CCI-002038', 'CCI-002361']
  tag nist: ['IA-11', 'AC-12']
end
