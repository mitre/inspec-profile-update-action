control 'SV-206433' do
  title 'The web server must be tuned to handle the operational requirements of the hosted application.'
  desc 'A Denial of Service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine what parameters are set to tune the web server.

Review the hosted applications along with risk analysis documents to determine the expected user traffic.

If the web server has not been tuned to avoid a DoS, this is a finding.'
  desc 'fix', 'Analyze the expected user traffic for the hosted applications.

Tune the web server to avoid a DoS condition under normal user traffic to the hosted applications.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6694r377891_chk'
  tag severity: 'medium'
  tag gid: 'V-206433'
  tag rid: 'SV-206433r879806_rule'
  tag stig_id: 'SRG-APP-000435-WSR-000148'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-6694r377892_fix'
  tag 'documentable'
  tag legacy: ['SV-70251', 'V-55997']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
