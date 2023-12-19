control 'SV-102623' do
  title 'Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.'
  desc 'Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

If "HttpOnly; secure" is not configured, this is a finding.

Review the code. If when creating cookies, the following is not occurring, this is a finding:

function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; })
  desc 'fix', 'Add this line to the "httpd.conf" file:

Header always edit Set-Cookie ^(.*)$ $1;HttpOnly;secure

Add the secure attribute to the JavaScript set cookie:

function setCookie() { document.cookie = "ALEPH_SESSION_ID = $SESS; path = /; secure"; }

"HttpOnly" cannot be used since by definition this is a cookie set by JavaScript.

Restart www_server and Apache.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91839r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92535'
  tag rid: 'SV-102623r1_rule'
  tag stig_id: 'AS24-W2-000470'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-98777r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
