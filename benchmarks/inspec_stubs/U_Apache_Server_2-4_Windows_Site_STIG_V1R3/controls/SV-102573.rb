control 'SV-102573' do
  title 'The Apache web server must limit the number of allowed simultaneous session requests.'
  desc 'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of denial-of-service (DoS) attacks.

Although there is some latitude concerning the settings, they should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', %q(Open the <'INSTALL PATH'>\conf\httpd.conf file with an editor and search for the following directive:

MaxKeepAliveRequests

Verify the value is "100" or greater.

If the directive is not set to "100" or greater, this is a finding.)
  desc 'fix', %q(Open the <'INSTALL PATH'>\conf\httpd.conf file with an editor and search for the following directive:

MaxKeepAliveRequests

Set the directive to a value of "100" or greater; add the directive if it does not exist.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92485'
  tag rid: 'SV-102573r1_rule'
  tag stig_id: 'AS24-W2-000010'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-98727r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
