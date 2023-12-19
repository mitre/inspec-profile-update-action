control 'SV-218736' do
  title 'The IIS 10.0 website session state cookie settings must be configured to Use Cookies mode.'
  desc "When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is stored in either a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the hijacking of a session along with all of the user's credentials.

When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and website will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised.

ASP.NET provides a session state, which is available as the HttpSessionState class, as a method of storing session-specific information visible only within the session. ASP.NET session state identifies requests from the same browser during a limited time window as a session and provides the ability to persist variable values for the duration of that session.

When using the URI mode for cookie settings under session state, IIS will reject and reissue session IDs that do not have active sessions. Configuring IIS to expire session IDs and regenerate tokens gives a potential attacker less time to capture a cookie and gain access to server content."
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:
Open the IIS 10.0 Manager.
Click the site name.
Under the "ASP.NET" section, select "Session State".
Under "Cookie Settings", verify the "Use Cookies" mode is selected from the "Mode:" drop-down list.
If the "Use Cookies" mode is selected, this is not a finding.

Alternative method:
Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".
If the "cookieless" is not set to "UseCookies", this is a finding.
Note: If IIS 10.0 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server: 

Open the IIS 10.0 Manager.

Click the site name.

Under the ASP.NET section, select "Session State".

Under "Cookie Settings", select the "Use Cookies" from the "Mode:" drop-down list.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20209r311106_chk'
  tag severity: 'medium'
  tag gid: 'V-218736'
  tag rid: 'SV-218736r558649_rule'
  tag stig_id: 'IIST-SI-000202'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-20207r311107_fix'
  tag 'documentable'
  tag legacy: ['SV-109297', 'V-100193']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
