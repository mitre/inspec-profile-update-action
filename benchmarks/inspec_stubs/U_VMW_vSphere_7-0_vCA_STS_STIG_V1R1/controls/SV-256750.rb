control 'SV-256750' do
  title 'The Security Token Service must generate log records during Java startup and shutdown.'
  desc 'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.

'
  desc 'check', 'At the command prompt, run the following command: 
 
# grep "1catalina.org.apache.juli.FileHandler" /usr/lib/vmware-sso/vmware-sts/conf/logging.properties 
 
Expected result: 
 
handlers = 1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler 
.handlers = 1catalina.org.apache.juli.FileHandler 
1catalina.org.apache.juli.FileHandler.level = FINE 
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs/tomcat 
1catalina.org.apache.juli.FileHandler.prefix = catalina. 
1catalina.org.apache.juli.FileHandler.bufferSize = -1 
1catalina.org.apache.juli.FileHandler.formatter = java.util.logging.SimpleFormatter 
org.apache.catalina.startup.Catalina.handlers = 1catalina.org.apache.juli.FileHandler 
 
If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open: 
 
/usr/lib/vmware-sso/vmware-sts/conf/logging.properties 
 
Ensure the "handlers" and ".handlers" lines are configured as follows: 
 
handlers = 1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler 
.handlers = 1catalina.org.apache.juli.FileHandler 
1catalina.org.apache.juli.FileHandler.level = FINE 
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs/tomcat 
1catalina.org.apache.juli.FileHandler.prefix = catalina. 
1catalina.org.apache.juli.FileHandler.bufferSize = -1 
1catalina.org.apache.juli.FileHandler.formatter = java.util.logging.SimpleFormatter 
org.apache.catalina.startup.Catalina.handlers = 1catalina.org.apache.juli.FileHandler 
 
Restart the service with the following command: 
 
# vmon-cli --restart sts'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA STS'
  tag check_id: 'C-60425r889218_chk'
  tag severity: 'medium'
  tag gid: 'V-256750'
  tag rid: 'SV-256750r889220_rule'
  tag stig_id: 'VCST-70-000006'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-60368r889219_fix'
  tag satisfies: ['SRG-APP-000089-WSR-000047', 'SRG-APP-000092-WSR-000055']
  tag 'documentable'
  tag cci: ['CCI-000169', 'CCI-001464']
  tag nist: ['AU-12 a', 'AU-14 (1)']
end
