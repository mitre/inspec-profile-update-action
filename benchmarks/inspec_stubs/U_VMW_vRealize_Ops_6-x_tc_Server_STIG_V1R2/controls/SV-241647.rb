control 'SV-241647' do
  title 'tc Server API must be configured with memory leak protection.'
  desc "The Java Runtime environment can cause a memory leak or lock files under certain conditions.  Without memory leak protection, tc Server HORIZON can continue to consume system resources which will lead to OutOfMemoryErrors when re-loading web applications.

Memory leaks occur when JRE code uses the context class loader to load a singleton as this will cause a memory leak if a web application class loader happens to be the context class loader at the time. The JreMemoryLeakPreventionListener class is designed to initialize these singletons when Tomcat's common class loader is the context class loader.

Proper use of JRE memory leak protection will ensure that the hosted application does not consume system resources and cause an unstable environment."
  desc 'check', 'At the command prompt, execute the following command: 

grep JreMemoryLeakPreventionListener /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml

If the JreMemoryLeakPreventionListener <Listener> node is not listed, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to the <Server> node.

Add '<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>' to the <Server> node.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44923r683801_chk'
  tag severity: 'medium'
  tag gid: 'V-241647'
  tag rid: 'SV-241647r879587_rule'
  tag stig_id: 'VROM-TC-000410'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-44882r683802_fix'
  tag 'documentable'
  tag legacy: ['SV-99579', 'V-88929']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
