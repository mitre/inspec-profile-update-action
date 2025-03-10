control 'SV-239669' do
  title 'The Security Token Service must fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Determining a safe state for failure and weighing that against a potential denial of service for users depends on what type of application the web server is hosting. For the Security Token Service, it is preferable that the service abort startup on any initialization failure rather than continuing in a degraded and potentially insecure state.'
  desc 'check', 'Connect to the PSC, whether external or embedded.

At the command line, execute the following command:

# grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Expected result:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Connect to the PSC, whether external or embedded.

Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties.

Add or change the following line:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42902r816730_chk'
  tag severity: 'medium'
  tag gid: 'V-239669'
  tag rid: 'SV-239669r879640_rule'
  tag stig_id: 'VCST-67-000018'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag fix_id: 'F-42861r816731_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
