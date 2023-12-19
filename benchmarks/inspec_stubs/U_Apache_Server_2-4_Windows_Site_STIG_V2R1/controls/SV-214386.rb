control 'SV-214386' do
  title 'The Apache web server must set an absolute timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after an absolute period of time, the user is forced to reauthenticate, guaranteeing the session is still in use. Enabling an absolute timeout for sessions closes sessions that are still active. Examples would be a runaway process accessing the web server or an attacker using a hijacked session to slowly probe the web server.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

Search for the following directive:

SessionMaxAge

Verify the value of "SessionMaxAge" is set to "600" or less.

If the "SessionMaxAge" does not exist or is set to more than "600", this is a finding.)
  desc 'fix', %q(Open the <'INSTALL PATH'>\conf\httpd.conf file.

Set the "SessionMaxAge" directive to a value of "600" or less; add the directive if it does not exist.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15597r803280_chk'
  tag severity: 'medium'
  tag gid: 'V-214386'
  tag rid: 'SV-214386r803282_rule'
  tag stig_id: 'AS24-W2-000640'
  tag gtitle: 'SRG-APP-000295-WSR-000012'
  tag fix_id: 'F-15595r803281_fix'
  tag 'documentable'
  tag legacy: ['SV-102647', 'V-92559']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
