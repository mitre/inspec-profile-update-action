control 'SV-239418' do
  title 'Performance Charts must fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Determining a safe state for failure and weighing that against a potential denial of service for users depends on what type of application the web server is hosting. For Performance Charts, it is preferable that the service abort startup on any initialization failure rather than continuing in a degraded, and potentially insecure, state.'
  desc 'check', 'At the command line, execute the following command:

# grep EXIT_ON_INIT_FAILURE /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties

Expected result:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE = true

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-perfcharts/tc-instance/conf/catalina.properties.

Add or change the following line:

org.apache.catalina.startup.EXIT_ON_INIT_FAILURE=true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Perfcharts Tomcat'
  tag check_id: 'C-42651r674975_chk'
  tag severity: 'medium'
  tag gid: 'V-239418'
  tag rid: 'SV-239418r879640_rule'
  tag stig_id: 'VCPF-67-000017'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag fix_id: 'F-42610r674976_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
