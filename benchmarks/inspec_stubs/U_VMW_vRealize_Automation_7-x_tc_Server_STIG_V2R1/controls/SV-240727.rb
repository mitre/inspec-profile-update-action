control 'SV-240727' do
  title 'tc Server VCAC must limit the number of maximum concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the maxThreads attribute.'
  desc 'check', 'At the command prompt, execute the following command:

grep maxThreads /etc/vcac/server.xml

If the value of "maxThreads" is not "1000" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vcac/server.xml.

Navigate to and locate <Executor>.

Configure the <Executor> with the value 'maxThreads="1000"'.

Note: The <Executor> node should be configured per the following:

<Executor
 maxThreads="1000"
 minSpareThreads="50"
 name="tomcatThreadPool"
 namePrefix="tomcat-http--"/>)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43960r673923_chk'
  tag severity: 'medium'
  tag gid: 'V-240727'
  tag rid: 'SV-240727r673925_rule'
  tag stig_id: 'VRAU-TC-000015'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-43919r673924_fix'
  tag 'documentable'
  tag legacy: ['SV-100535', 'V-89885']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
