control 'SV-214341' do
  title 'The Apache web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to reauthenticate, guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the Apache web server or an attacker using a hijacked session to slowly probe the Apache web server.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

Search for the following directive:

SessionMaxAge

Verify the value of "SessionMaxAge" is set to "600" or less.

If the "SessionMaxAge" does not exist or is set to more than "600", this is a finding.)
  desc 'fix', %q(Open the <'INSTALL PATH'>\conf\httpd.conf file.

Set the "SessionMaxAge" directive to a value of "600" or less; add the directive if it does not exist.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15553r803286_chk'
  tag severity: 'medium'
  tag gid: 'V-214341'
  tag rid: 'SV-214341r879673_rule'
  tag stig_id: 'AS24-W1-000640'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-15551r803287_fix'
  tag 'documentable'
  tag legacy: ['SV-102521', 'V-92433']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
