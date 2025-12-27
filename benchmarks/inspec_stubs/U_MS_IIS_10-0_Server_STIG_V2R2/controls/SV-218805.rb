control 'SV-218805' do
  title 'The IIS 10.0 web server must accept only system-generated session identifiers.'
  desc 'ASP.NET provides a session state, which is available as the HttpSessionState class, as a method of storing session-specific information that is visible only within the session. ASP.NET session state identifies requests from the same browser during a limited time window as a session and provides the ability to persist variable values for the duration of that session.

When using the URI mode for cookie settings under session state, IIS will reject and reissue session IDs that do not have active sessions. Configuring IIS to expire session IDs and regenerate tokens gives a potential attacker less time to capture a cookie and gain access to server content.'
  desc 'check', 'Open the IIS 10.0 Manager.
Click the IIS 10.0 web server name.
Under the "ASP.NET" section, select "Session State".
Under "Cookie Settings", verify the "Use Cookies" mode is selected from the "Mode:" drop-down list.
Under Time-out (in minutes), verify “20 minutes or less” is selected.
If the "Use Cookies” mode is selected and Time-out (in minutes) is configured for “20 minutes or less”, this is not a finding.

Alternative method:

Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".
If the "cookieless" is not set to "UseCookies", this is a finding.

Note: If IIS 10.0 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.'
  desc 'fix', 'Open the IIS 10.0 Manager.

Click the IIS 10.0 web server name.

Under the "ASP.NET" section, select "Session State".

Under "Cookie Settings", select the "Use Cookies" mode from the "Mode:" drop-down list.

Under “Time-out (in minutes), enter a value of “20 or less”.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20277r310890_chk'
  tag severity: 'medium'
  tag gid: 'V-218805'
  tag rid: 'SV-218805r561041_rule'
  tag stig_id: 'IIST-SV-000135'
  tag gtitle: 'SRG-APP-000223-WSR-000145'
  tag fix_id: 'F-20275r310891_fix'
  tag 'documentable'
  tag legacy: ['SV-109249', 'V-100145']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
