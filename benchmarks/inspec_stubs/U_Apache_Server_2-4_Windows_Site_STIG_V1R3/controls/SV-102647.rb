control 'SV-102647' do
  title 'The Apache web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to reauthenticate, guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the web server or an attacker using a hijacked session to slowly probe the web server.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "SessionMaxAge" directive exists.

If it does not exist, this is a finding. 

If the "SessionMaxAge" directive exists but is not set to "1", this is a finding.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and add or set the "SessionMaxAge" directive to "1".)
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92559'
  tag rid: 'SV-102647r1_rule'
  tag stig_id: 'AS24-W2-000640'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-98801r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
