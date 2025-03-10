control 'SV-213523' do
  title 'Welcome Web Application must be disabled.'
  desc 'The Welcome to JBoss web page provides a redirect to the JBoss admin console, which, by default, runs on TCP 9990 as well as redirects to the Online User Guide and Online User Groups hosted at locations on the Internet.  The welcome page is unnecessary and should be disabled or replaced with a valid web page.'
  desc 'check', 'Use a web browser and browse to HTTP://JBOSS SERVER IP ADDRESS:8080

If the JBoss Welcome page is displayed, this is a finding.'
  desc 'fix', 'Use the Management CLI script JBOSS_HOME/bin/jboss-cli.sh to run the following command. You may need to change the profile to modify a different managed domain profile, or remove the "/profile=default" portion of the command for a standalone server.

"/profile=default/subsystem=web/virtual-server=default-host:writeattribute(name=enable-welcome-root,value=false)"

To configure your web application to use the root context (/) as its URL address, modify the applications jboss-web.xml, which is located in the applications META-INF/ or WEB-INF/ directory. Replace its <context-root> directive with one that looks like the following:

<jboss-web>
         <context-root>/</context-root>
</jboss-web>'
  impact 0.3
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14746r296235_chk'
  tag severity: 'low'
  tag gid: 'V-213523'
  tag rid: 'SV-213523r615939_rule'
  tag stig_id: 'JBOS-AS-000245'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-14744r296236_fix'
  tag 'documentable'
  tag legacy: ['SV-76761', 'V-62271']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
