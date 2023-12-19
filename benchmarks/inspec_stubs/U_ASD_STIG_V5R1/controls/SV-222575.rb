control 'SV-222575' do
  title 'The application must set the HTTPOnly flag on session cookies.'
  desc 'HTTPOnly is a flag included in a Set-Cookie HTTP response header. If the HTTPOnly flag is included in the HTTP response header, the cookie cannot be accessed through client side scripts like JavaScript.

If the HTTPOnly flag is set, even if a cross-site scripting (XSS) flaw in the application exists, and a user accidentally accesses a link that exploits this flaw, the browser will not reveal the cookie to a third party.

The HTTPOnly setting is browser dependent however most popular browsers support the feature. If a browser does not support HTTPOnly and a website attempts to set an HTTPOnly cookie, the HTTPOnly flag will be ignored by the browser, thus creating a traditional, script accessible cookie. As a result, the cookie (typically the session cookie) becomes vulnerable to theft or modification by a malicious script running on the client system.'
  desc 'check', 'Review the application documentation and interview the application administrator to identify when session cookies are created.

Identify any mitigating controls the application developer may have implemented. Examples include utilizing a separate Web Application Firewall that is configured to provide this capability or configuring the web server with Mod_Security or ESAPI WAF with the HTTPOnly flag directives enabled.

Reference the most recent vulnerability scan documentation.

Verify the configuration settings for the scan include web application checks including HTTPOnly tests.

Review the scan results and determine if vulnerabilities related to HTTPOnly flag not being set for session cookies have been identified.

Utilize a web browser or other web application diagnostic tool to view the session cookies the application sets on the client.

Internet Explorer versions 8, 9, and 10 includes a utility called Developer tools.

Access the application website and establish an application session.

Access the page that sets the session cookie.

Press “F12” to open Developer Tools.

Select "cache" and then "view cookie information".

Identify the session cookies. An example of an HTTPOnly session cookie is as follows:

Set-Cookie: SessionId=z5ymkk45aworjo2l31tlhqqv; path=/; HttpOnly

If the application does not set the HTTPOnly flag on session cookies or if the application administrator cannot demonstrate mitigating controls, this is a finding.'
  desc 'fix', 'Configure the application to set the HTTPOnly flag on session cookies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24245r493633_chk'
  tag severity: 'medium'
  tag gid: 'V-222575'
  tag rid: 'SV-222575r508029_rule'
  tag stig_id: 'APSC-DV-002210'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-24234r493634_fix'
  tag 'documentable'
  tag legacy: ['V-70201', 'SV-84823']
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
