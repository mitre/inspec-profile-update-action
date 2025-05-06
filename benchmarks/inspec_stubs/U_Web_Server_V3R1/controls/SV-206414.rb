control 'SV-206414' do
  title 'The web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to re-authenticate guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the web server or an attacker using a hijacked session to slowly probe the web server.'
  desc 'check', 'Review the web server documentation and deployed configuration to verify that the web server is configured to close sessions after an absolute period of time.

If the web server is not configured to close sessions after an absolute period of time, this is a finding.'
  desc 'fix', 'Configure the web server to close sessions after an absolute period of time.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6675r377834_chk'
  tag severity: 'medium'
  tag gid: 'V-206414'
  tag rid: 'SV-206414r855036_rule'
  tag stig_id: 'SRG-APP-000295-WSR-000012'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-6675r377835_fix'
  tag 'documentable'
  tag legacy: ['SV-70205', 'V-55951']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
