control 'SV-222971' do
  title 'Tomcat servers must mutually authenticate proxy or load balancer connections.'
  desc 'Tomcat servers are often placed behind a proxy when exposed to both trusted and untrusted networks. This is done for security and performance reasons.  Tomcat does provide an HTTP server that can be configured to make hosted applications available to clients directly. However, this HTTP server has performance limitations and is not intended to be used on an enterprise scale. Exposing this service to untrusted networks also violates the layered security model and creates elevated risk of attack. To address these issues, a proxy or load balancer can be placed in front of the Tomcat server. To ensure the proxied connection is not spoofed, SSL mutual authentication must be employed between Tomcat and the proxy.

Not all Tomcat systems will have an RMF system categorization that warrants mutual authentication protections. The site must determine if mutual authentication is warranted based on their system RMF categorization and data protection requirements. If the site determines that MA is not a requirement, they can document a risk acceptance for not mutually authenticating proxy or load balancer connections due to operational issues, or when the RMF system categorization does not warrant the added level of protection.'
  desc 'check', 'Review system security plan and/or system architecture documentation and interview the system admin. Identify any proxy servers or load balancers that provide services for the Tomcat server. If there are no load balancers or proxies in use, this is not a finding.

If there is a documented risk acceptance for not mutually authenticating proxy or load balancer connections due to operational issues, or RMF system categorization this is not a finding.

Using the aforementioned documentation, identify each Tomcat IP address that is served by a load balancer or proxy.  

From the Tomcat server as a privileged user, review the $CATALINA_BASE/conf/server.xml file.  Review each <Connector> element for the address setting and the clientAuth setting.

sudo grep -i -B1 -A5 connector $CATALINA_BASE/conf/server.xml

If a connector has a configured IP address that is proxied or load balanced and the clientAuth setting is not "true", this is a finding.'
  desc 'fix', 'From the Tomcat server as a privileged user, edit the $CATALINA_BASE/conf/server.xml file.  

Modify each <Connector> element where the IP address is behind a proxy or load balancer.

Set clientAuth="true" then identify the applications that are associated with the connector and edit the associated web.xml files.  Assure the <auth-method> is set to CLIENT-CERT.'
  impact 0.5
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24643r426357_chk'
  tag severity: 'medium'
  tag gid: 'V-222971'
  tag rid: 'SV-222971r879636_rule'
  tag stig_id: 'TCAT-AS-000800'
  tag gtitle: 'SRG-APP-000219-AS-000147'
  tag fix_id: 'F-24632r426358_fix'
  tag 'documentable'
  tag legacy: ['SV-111465', 'V-102525']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
