control 'SV-100533' do
  title 'tc Server VCO must limit the number of maximum concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the maxThreads attribute.'
  desc 'check', 'At the command prompt, execute the following command:

grep maxThreads /etc/vco/app-server/server.xml

If the value of "maxThreads" is not "300" or is missing, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vco/app-server/server.xml.

Navigate to and locate the <Connector> node.

Configure the <Connector> with the value 'maxThreads="300"'.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89575r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89883'
  tag rid: 'SV-100533r1_rule'
  tag stig_id: 'VRAU-TC-000010'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-96625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
