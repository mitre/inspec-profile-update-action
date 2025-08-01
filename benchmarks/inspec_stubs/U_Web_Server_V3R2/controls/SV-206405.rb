control 'SV-206405' do
  title 'The web server must be built to fail to a known safe state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Determining a safe state for failure and weighing that against a potential DoS for users depends on what type of application the web server is hosting. For an application presenting publicly available information that is not critical, a safe state for failure might be to shut down for any type of failure; but for an application that presents critical and timely information, a shutdown might not be the best state for all failures. 

Performing a proper risk analysis of the hosted applications and configuring the web server according to what actions to take for each failure condition will provide a known fail safe state for the web server.'
  desc 'check', 'Review the web server documentation, deployed configuration, and risk analysis documentation to determine whether the web server will fail to known states for system initialization, shutdown, or abort failures.

If the web server will not fail to known state, this is a finding.'
  desc 'fix', 'Configure the web server to fail to the states of operation during system initialization, shutdown, or abort failures found in the risk analysis.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6666r377807_chk'
  tag severity: 'medium'
  tag gid: 'V-206405'
  tag rid: 'SV-206405r879640_rule'
  tag stig_id: 'SRG-APP-000225-WSR-000140'
  tag gtitle: 'SRG-APP-000225'
  tag fix_id: 'F-6666r377808_fix'
  tag 'documentable'
  tag legacy: ['SV-54388', 'V-41811']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
