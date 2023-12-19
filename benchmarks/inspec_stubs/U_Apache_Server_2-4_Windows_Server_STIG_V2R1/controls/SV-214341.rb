control 'SV-214341' do
  title 'The Apache web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to reauthenticate, guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the Apache web server or an attacker using a hijacked session to slowly probe the Apache web server.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

Verify the "SessionMaxAge" directive exists.

If it does not exist, this is a finding.

If the "SessionMaxAge" directive exists but is not set to at least "1", this is a finding.)
  desc 'fix', %q(Edit the <'INSTALL PATH'>\conf\httpd.conf file and add or set the "SessionMaxAge" directive to "1" or more.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15553r277526_chk'
  tag severity: 'medium'
  tag gid: 'V-214341'
  tag rid: 'SV-214341r557320_rule'
  tag stig_id: 'AS24-W1-000640'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-15551r557319_fix'
  tag 'documentable'
  tag legacy: ['V-92433', 'SV-102521']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
