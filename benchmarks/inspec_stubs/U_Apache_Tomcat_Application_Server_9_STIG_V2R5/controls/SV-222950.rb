control 'SV-222950' do
  title 'Stack tracing must be disabled.'
  desc 'Stack tracing provides debugging information from the application call stacks when a runtime error is encountered. If stack tracing is left enabled, Tomcat will provide this call stack information to the requestor which could result in the loss of sensitive information or data that could be used to compromise the system.  As with all STIG settings, it is acceptable to temporarily enable for troubleshooting and debugging purposes but the setting must not be left enabled after troubleshooting tasks have been completed.'
  desc 'check', 'From the Tomcat server run the following OS command:

sudo cat $CATALINA_BASE/conf/server.xml | grep -i connector 

Review each connector element, ensure each connector does not have an "allowTrace" setting or ensure the "allowTrace" setting is set to false.

<Connector ... allowTrace="false" />

Do the same for each application by checking every $CATALINA_BASE/webapps/<APP_NAME>/WEBINF/web.xml file on the system.

sudo cat $CATALINA_BASE/webapps/<APP_NAME>/WEBINF/web.xml |grep -i connector 

If a connector element in the server.xml file or in any of the <APP NAME>/WEBINF/web.xml files contains the "allow Trace = true" statement, this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, edit the xml files containing the "allow Trace=true" statement.

Remove the "allow Trace=true" statement from the affected xml configuration files and restart the Tomcat server:
sudo systemctl restart tomcat
sudo systemctl daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24622r426294_chk'
  tag severity: 'medium'
  tag gid: 'V-222950'
  tag rid: 'SV-222950r879587_rule'
  tag stig_id: 'TCAT-AS-000470'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24611r426295_fix'
  tag 'documentable'
  tag legacy: ['SV-111425', 'V-102483']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
