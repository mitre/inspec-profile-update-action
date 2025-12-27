control 'SV-240795' do
  title 'tc Server HORIZON must be configured with memory leak protection.'
  desc "The Java Runtime environment can cause a memory leak or lock files under certain conditions. Without memory leak protection, tc Server HORIZON can continue to consume system resources that will lead to OutOfMemoryErrors when reloading web applications.

Memory leaks occur when JRE code uses the context class loader to load a singleton as this will cause a memory leak if a web application class loader happens to be the context class loader at the time. The JreMemoryLeakPreventionListener class is designed to initialize these singletons when Tomcat's common class loader is the context class loader.

Proper use of JRE memory leak protection will ensure that the hosted application does not consume system resources and cause an unstable environment."
  desc 'check', 'At the command prompt, execute the following command: 

grep JreMemoryLeakPreventionListener /opt/vmware/horizon/workspace/conf/server.xml

If the JreMemoryLeakPreventionListener <Listener> node is not listed, this is a finding.'
  desc 'fix', %q(Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to the <Server> node.

Add '<Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener"/>' to the <Server> node.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44028r674127_chk'
  tag severity: 'medium'
  tag gid: 'V-240795'
  tag rid: 'SV-240795r879587_rule'
  tag stig_id: 'VRAU-TC-000390'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag fix_id: 'F-43987r674128_fix'
  tag 'documentable'
  tag legacy: ['SV-100673', 'V-90023']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
