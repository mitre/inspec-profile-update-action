control 'SV-214332' do
  title 'Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.'
  desc 'Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

If "HttpOnly;secure" is not configured, this is a finding.

Review the code. If when creating cookies, the following is not occurring, this is a finding:

function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; })
  desc 'fix', 'Add this line to "httpd.conf" file:

Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure

Add the secure attribute to the JavaScript set cookie:

function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; } 

HttpOnly cannot be used since by definition this is a cookie set by JavaScript.

Restart the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15544r277499_chk'
  tag severity: 'medium'
  tag gid: 'V-214332'
  tag rid: 'SV-214332r879638_rule'
  tag stig_id: 'AS24-W1-000470'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-15542r277500_fix'
  tag 'documentable'
  tag legacy: ['SV-102495', 'V-92407']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
