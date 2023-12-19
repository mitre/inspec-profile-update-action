control 'SV-100713' do
  title 'tc Server VCO must be built to fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Determining a safe state for failure and weighing that against a potential DoS for users depends on what type of application the web server is hosting. For an application presenting publicly available information that is not critical, a safe state for failure might be to shut down for any type of failure; but for an application that presents critical and timely information, a shutdown might not be the best state for all failures. 

Performing a proper risk analysis of the hosted applications and configuring the web server according to what actions to take for each failure condition will provide a known fail safe state for the web server. The VMware engineering process includes regression testing of new and modified components before they become part of the production build process.'
  desc 'check', 'At the command line, execute the following command:

grep EXIT_ON_INIT_FAILURE /etc/vco/app-server/catalina.properties

If the "org.apache.catalina.startup.EXIT_ON_INIT_FAILURE" setting is not set to "true" or is missing, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vco/app-server/catalina.properties.

Configure the setting "org.apache.catalina.startup.EXIT_ON_INIT_FAILURE" with the value "true".

Note: The word "true" should not be surrounded with any quote characters.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90063'
  tag rid: 'SV-100713r1_rule'
  tag stig_id: 'VRAU-TC-000560'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag fix_id: 'F-96805r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
