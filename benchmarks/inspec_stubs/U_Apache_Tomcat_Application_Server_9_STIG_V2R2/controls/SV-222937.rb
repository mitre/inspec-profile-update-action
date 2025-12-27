control 'SV-222937' do
  title 'Tomcat servers behind a proxy or load balancer must log client IP.'
  desc 'When running Tomcat behind a load balancer or proxy, default behavior is for Tomcat to log the proxy or load balancer IP address as the client IP. Desired behavior is to log the actual client IP rather than the proxy IP address. The RemoteIpValve logging component instructs Tomcat to grab the HTTP header X-Forwarded-For and use that for access logging.

Tomcat will identify 127.0.0.1, class A and class C RFC1918 addresses as internal proxy addresses; however, if the proxy has a routable IP or a class B private network address space (172.16.0.0/12), the user must also verify the "internalProxies setting is configured to reflect the proxy IP address.'
  desc 'check', 'Review the System Security Plan and determine if the Tomcat server resides behind a proxy server or load balancer. If the Tomcat server is not behind a proxy server or load balancer, this requirement is NA. 

From the Tomcat server run the following command:

sudo grep -i RemoteIpValve $CATALINA_BASE/conf/server.xml file.

If the results are empty or if the requestAttributesEnabled setting is not configured as "True", this is a finding.

sudo grep -i AccessLogValve $CATALINA_BASE/conf/server.xml file.

If the requestAttributesEnabled setting is not configured as "True", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user: 

Edit the $CATALINA_BASE/conf/server.xml file.

Only execute this first step if the proxy server is using a routable IP address or an RFC 1918 Class B address space: Add or edit the RemoteIpValve and configure the internalProxies setting to reflect the proxy addresses.

Modify the AccessLogValve and configure the requestAttributesEnabled setting = "True".

EXAMPLE:

<Valve className="org.apache.catalina.valves.RemoteIpValve" internalProxies="172.16.0.10|172.16.0.11" />

<Valve className="org.apache.catalina.valves.AccessLogValve"
  directory="logs"
  prefix="access"
  suffix=".log"
  pattern="combined"
  renameOnRotate="true"
  requestAttributesEnabled="true"
/>

Restart Tomcat:
sudo systemctl restart tomcat
sudo systemctl tomcat daemon-reload'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24609r426255_chk'
  tag severity: 'medium'
  tag gid: 'V-222937'
  tag rid: 'SV-222937r615938_rule'
  tag stig_id: 'TCAT-AS-000170'
  tag gtitle: 'SRG-APP-000089-AS-000050'
  tag fix_id: 'F-24598r426256_fix'
  tag 'documentable'
  tag legacy: ['SV-111405', 'V-102457']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
