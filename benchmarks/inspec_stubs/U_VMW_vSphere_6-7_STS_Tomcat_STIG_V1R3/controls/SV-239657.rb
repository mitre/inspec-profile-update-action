control 'SV-239657' do
  title 'The Security Token Service must generate log records during Java startup and shutdown.'
  desc 'Logging must be started as soon as possible when a service starts and as late as possible when a service is stopped. Many forms of suspicious actions can be detected by analyzing logs for unexpected service starts and stops. Also, by starting to log immediately after a service starts, it becomes more difficult for suspicious activity to go unlogged.'
  desc 'check', 'Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# grep "1catalina.org.apache.juli.FileHandler" /usr/lib/vmware-sso/vmware-sts/conf/logging.properties

Expected result:

handlers = 1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler
.handlers = 1catalina.org.apache.juli.FileHandler
1catalina.org.apache.juli.FileHandler.level = FINE
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs
1catalina.org.apache.juli.FileHandler.prefix = catalina.
1catalina.org.apache.juli.FileHandler.bufferSize = -1

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Connect to the PSC, whether external or embedded.

Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/logging.properties.

Ensure that the "handlers" and ".handlers" lines are configured as follows:

handlers = 1catalina.org.apache.juli.FileHandler, 2localhost.org.apache.juli.FileHandler, 3manager.org.apache.juli.FileHandler, 4host-manager.org.apache.juli.FileHandler, java.util.logging.ConsoleHandler

.handlers = 1catalina.org.apache.juli.FileHandler

Ensure that the following lines are present:

1catalina.org.apache.juli.FileHandler.level = FINE
1catalina.org.apache.juli.FileHandler.directory = ${catalina.base}/logs
1catalina.org.apache.juli.FileHandler.prefix = catalina.
1catalina.org.apache.juli.FileHandler.bufferSize = -1'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42890r816694_chk'
  tag severity: 'medium'
  tag gid: 'V-239657'
  tag rid: 'SV-239657r879559_rule'
  tag stig_id: 'VCST-67-000006'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-42849r816695_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
