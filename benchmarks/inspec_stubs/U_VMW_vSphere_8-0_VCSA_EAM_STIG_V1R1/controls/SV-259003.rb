control 'SV-259003' do
  title 'The vCenter ESX Agent Manager service must limit the number of maximum concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. In Tomcat, each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the maxThreads attribute.

'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

maxThreads="300"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Navigate to the <Executor> node with the name of tomcatThreadPool and configure with the value "maxThreads="300"".

Note: The <Executor> node should be configured similar to the following:

<Executor maxThreads="300"
                minSpareThreads="50"
                name="tomcatThreadPool"
                namePrefix="tomcat-http--"/>

Restart the service with the following command:

# vmon-cli --restart eam'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA EAM'
  tag check_id: 'C-62743r934665_chk'
  tag severity: 'medium'
  tag gid: 'V-259003'
  tag rid: 'SV-259003r934667_rule'
  tag stig_id: 'VCEM-80-000001'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-62652r934666_fix'
  tag satisfies: ['SRG-APP-000001-AS-000001', 'SRG-APP-000435-AS-000163']
  tag 'documentable'
  tag cci: ['CCI-000054', 'CCI-002385']
  tag nist: ['AC-10', 'SC-5 a']
end
