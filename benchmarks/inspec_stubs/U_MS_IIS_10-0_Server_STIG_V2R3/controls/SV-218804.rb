control 'SV-218804' do
  title 'The IIS 10.0 web server must use cookies to track session state.'
  desc 'Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

Using URI will embed the session ID as a query string in the Uniform Resource Identifier (URI) request and then the URI is redirected to the originally requested URL. The changed URI request is used for the duration of the session, so no cookie is necessary.

By requiring expired session IDs to be regenerated while using URI, potential attackers have less time to capture a cookie and gain access to the Web server content.

'
  desc 'check', 'Open the IIS 10.0 Manager.
Click the IIS 10.0 web server name.
Under "ASP.Net", double-click the "Session State" icon.
Under "Cookie Settings", verify the "Mode" has "Use Cookies" selected from the drop-down list.
If the "Cookie Settings" "Mode" is not set to "Use Cookies", this is a finding.

Alternative method:

Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".
If the "cookieless" is not set to "UseCookies", this is a finding.

Note: If IIS 10.0 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under "ASP.Net", double-click the "Session State" icon.

Under "Cookie Settings", select "Use Cookies” from the "Mode" drop-down list.

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20276r310887_chk'
  tag severity: 'medium'
  tag gid: 'V-218804'
  tag rid: 'SV-218804r561041_rule'
  tag stig_id: 'IIST-SV-000134'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-20274r310888_fix'
  tag satisfies: ['SRG-APP-000223-WSR-000011', 'SRG-APP-000220-WSR-000201']
  tag 'documentable'
  tag legacy: ['SV-109247', 'V-100143']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
