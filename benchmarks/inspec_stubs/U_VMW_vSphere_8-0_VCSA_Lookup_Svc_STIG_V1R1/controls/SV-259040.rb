control 'SV-259040' do
  title 'The vCenter Lookup service must produce log records containing sufficient information regarding event details.'
  desc %q(Remote access can be exploited by an attacker to compromise the server. By recording all remote access activities, it will be possible to determine the attacker's location, intent, and degree of success.

Tomcat can be configured with an "AccessLogValve", a component that can be inserted into the request processing pipeline to provide robust access logging. The "AccessLogValve" creates log files in the same format as those created by standard web servers. When "AccessLogValve" is properly configured, log files will contain all the forensic information necessary in the case of a security incident.

)
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.AccessLogValve"]/@pattern' /usr/lib/vmware-lookupsvc/conf/server.xml

Example result:

pattern="%t %I [Request] &quot;%{User-Agent}i&quot; %{X-Forwarded-For}i/%h:%{remote}p %l %u to local %{local}p - &quot;%r&quot; %H %m %U%q    [Response] %s - %b bytes    [Perf] process %Dms / commit %Fms / conn [%X]"

Required elements:

%h %{X-Forwarded-For}i %l %t %u &quot;%r&quot; %s %b

If the log pattern does not contain the required elements in any order, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Inside the <Host> node, find the "AccessLogValve" <Valve> node and replace the "pattern" element as follows:

pattern="%t %I [Request] &quot;%{User-Agent}i&quot; %{X-Forwarded-For}i/%h:%{remote}p %l %u to local %{local}p - &quot;%r&quot; %H %m %U%q    [Response] %s - %b bytes    [Perf] process %Dms / commit %Fms / conn [%X]"

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Lookup Service'
  tag check_id: 'C-62780r934776_chk'
  tag severity: 'medium'
  tag gid: 'V-259040'
  tag rid: 'SV-259040r934778_rule'
  tag stig_id: 'VCLU-80-000014'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag fix_id: 'F-62689r934777_fix'
  tag satisfies: ['SRG-APP-000095-AS-000056', 'SRG-APP-000016-AS-000013', 'SRG-APP-000096-AS-000059', 'SRG-APP-000097-AS-000060', 'SRG-APP-000098-AS-000061', 'SRG-APP-000099-AS-000062', 'SRG-APP-000100-AS-000063', 'SRG-APP-000080-AS-000045', 'SRG-APP-000089-AS-000050', 'SRG-APP-000090-AS-000051', 'SRG-APP-000091-AS-000052', 'SRG-APP-000343-AS-000030', 'SRG-APP-000375-AS-000211', 'SRG-APP-000495-AS-000220', 'SRG-APP-000499-AS-000224', 'SRG-APP-000503-AS-000228']
  tag 'documentable'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000166', 'CCI-000169', 'CCI-000171', 'CCI-000172', 'CCI-001487', 'CCI-001889', 'CCI-002234']
  tag nist: ['AC-17 (1)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-10', 'AU-12 a', 'AU-12 b', 'AU-12 c', 'AU-3 f', 'AU-8 b', 'AC-6 (9)']
end
