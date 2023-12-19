control 'SV-240747' do
  title 'tc Server VCAC must generate log records for user access and authentication events.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

As a Tomcat derivative, tc Server can be configured with an AccessLogValve. A Valve element represents a component that can be inserted into the request processing pipeline. The pattern attribute of the AccessLogValve controls which data gets logged.'
  desc 'check', 'Navigate to and open /etc/vcac/server.xml.

Navigate to the <Host> node.
 
Verify that the node contains a <Valve className="org.apache.catalina.valves.AccessLogValve"> node.

If an "AccessLogValve" is not configured correctly or is missing, this is a finding.

Note: The "AccessLogValve" should be configured as follows:

<Valve className="org.apache.catalina.valves.AccessLogValve"
 checkExists="true" 
 directory="logs"
 pattern="%h %l %u %t &quot;%r&quot; %s %b"
 prefix="access_log"
 requestAttributesEnabled="true"
 rotatable="false"
 suffix=".txt"/>'
  desc 'fix', 'Navigate to and open /etc/vcac/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <AccessLogValve> below.

Note: The "AccessLogValve" should be configured as follows:

<Valve className="org.apache.catalina.valves.AccessLogValve"
 checkExists="true" 
 directory="logs"
 pattern="%h %l %u %t &quot;%r&quot; %s %b"
 prefix="access_log"
 requestAttributesEnabled="true"
 rotatable="false"
 suffix=".txt"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43980r674407_chk'
  tag severity: 'medium'
  tag gid: 'V-240747'
  tag rid: 'SV-240747r674408_rule'
  tag stig_id: 'VRAU-TC-000120'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-43939r673984_fix'
  tag 'documentable'
  tag legacy: ['SV-100573', 'V-89923']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
