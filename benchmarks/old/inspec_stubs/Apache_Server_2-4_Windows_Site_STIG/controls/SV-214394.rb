control 'SV-214394' do
  title 'Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.'
  desc 'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e., HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.'
  desc 'check', 'Verify the  "session_cookie_module"  module is installed.

Inspect the httpd.conf file to confirm the "session_cookie_module" is being used.

If the "session_cookie_module" module is not being used, this is a finding.

Search for the "Session" and "SessionCookieName" directives.

If "Session" is not "on" and "SessionCookieName" does not contain "httpOnly" and "secure", this is a finding.'
  desc 'fix', 'Set "Session" to "on". 

Ensure the "SessionCookieName" directive includes "httpOnly" and "secure".'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15605r803283_chk'
  tag severity: 'medium'
  tag gid: 'V-214394'
  tag rid: 'SV-214394r803285_rule'
  tag stig_id: 'AS24-W2-000870'
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag fix_id: 'F-15603r803284_fix'
  tag 'documentable'
  tag legacy: ['SV-102943', 'V-92855']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
