control 'SV-99465' do
  title 'tc Server API must record user access in a format that enables monitoring of remote access.'
  desc "Remote access can be exploited by an attacker to compromise the server. By recording all remote access activities, it will be possible to determine the attacker's location, intent, and degree of success.

As a Tomcat derivative, tc Server can be configured with an “AccessLogValve”. A Valve element represents a component that can be inserted into the request processing pipeline. The Access Log Valve creates log files in the same format as those created by standard web servers."
  desc 'check', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to the <Host> node.

Verify that the node contains a <Valve className="org.apache.catalina.valves.AccessLogValve"> node.

If an “AccessLogValve” is not configured correctly or is missing, this is a finding.

Note: The “AccessLogValve” should be configured as follows:

                <Valve className="org.apache.catalina.valves.AccessLogValve"
                       directory="logs"
                       pattern="%h %l %u %t &quot;%r&quot; %s %b"
                       prefix="localhost_access_log."
                       suffix=".txt"/>'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <AccessLogValve> below.

Note: The “AccessLogValve” should be configured as follows: 

                <Valve className="org.apache.catalina.valves.AccessLogValve"
                       directory="logs"
                       pattern="%h %l %u %t &quot;%r&quot; %s %b"
                       prefix="localhost_access_log."
                       suffix=".txt"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88507r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88815'
  tag rid: 'SV-99465r1_rule'
  tag stig_id: 'VROM-TC-000105'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-95557r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
