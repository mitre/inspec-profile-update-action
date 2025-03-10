control 'SV-239744' do
  title 'vSphere Client must limit the number of concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. In Virgo, each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the "maxThreads" attribute.'
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@maxThreads' /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

maxThreads="800" maxThreads="800"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

Configure each <Connector> node with the following:

maxThreads="800"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42977r679457_chk'
  tag severity: 'medium'
  tag gid: 'V-239744'
  tag rid: 'SV-239744r879511_rule'
  tag stig_id: 'VCFL-67-000002'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-42936r679458_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
