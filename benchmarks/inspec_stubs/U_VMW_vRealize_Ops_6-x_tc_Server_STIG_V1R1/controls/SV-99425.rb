control 'SV-99425' do
  title 'tc Server UI must limit the number of maximum concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a denial-of-service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the “maxThreads” attribute.'
  desc 'check', 'At the command prompt, execute the following command:

grep maxThreads /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml

If the value of “maxThreads” is not “300” or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to and locate <Executor>.

Configure the <Executor> with the value 'maxThreads= "300"'.

Note: The <Executor> node should be configured per the below:

        <Executor maxThreads="300"
                  minSpareThreads="50"
                  name="tomcatThreadPool"
                  namePrefix="tomcat-http--"/>)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88467r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88775'
  tag rid: 'SV-99425r1_rule'
  tag stig_id: 'VROM-TC-000005'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-95517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
