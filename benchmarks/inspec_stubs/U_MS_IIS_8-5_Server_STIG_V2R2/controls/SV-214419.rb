control 'SV-214419' do
  title 'The IIS 8.5 web server must use cookies to track session state.'
  desc 'Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

Cookies associate session information with client information for the duration of a user’s connection to a website. Using cookies is a more efficient way to track session state than any of the methods that do not use cookies because cookies do not require any redirection.'
  desc 'check', 'Note: If IIS 8.5 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.

Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Under "ASP.Net", double-click on the "Session State" icon.
Under "Cookie Settings", verify the "Mode" has "Use Cookies" selected from the drop-down list.

If the "Cookie Settings" "Mode" is not set to "Use Cookies", this is a finding.

Alternative method:
Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".

If the "cookieless" is not set to "UseCookies", this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under "ASP.Net", double-click on the "Session State" icon.

Under "Cookie Settings", select "Use Cookies” from the "Mode" drop-down list.

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15629r505354_chk'
  tag severity: 'medium'
  tag gid: 'V-214419'
  tag rid: 'SV-214419r508658_rule'
  tag stig_id: 'IISW-SV-000134'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-15627r505355_fix'
  tag 'documentable'
  tag legacy: ['SV-91421', 'V-76725']
  tag cci: ['CCI-001185', 'CCI-001664']
  tag nist: ['SC-23 (1)', 'SC-23 (3)']
end
