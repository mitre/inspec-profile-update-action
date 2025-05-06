control 'SV-214420' do
  title 'The IIS 8.5 web server must limit the amount of time a cookie persists.'
  desc 'ASP.NET provides a session state, which is available as the HttpSessionState class, as a method of storing session-specific information that is visible only within the session. ASP.NET session state identifies requests from the same browser during a limited time window as a session, and provides the ability to persist variable values for the duration of that session.

Cookies associate session information with client information for the duration of a user’s connection to a website. Using cookies is a more efficient way to track session state than any of the methods that do not use cookies because cookies do not require any redirection.'
  desc 'check', 'Note: If IIS 8.5 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.

Open the IIS 8.5 Manager.
Click the IIS 8.5 web server name.
Under the "ASP.NET" section, select "Session State".
Under "Cookie Settings", verify the "Use Cookies" mode is selected from the "Mode:" drop-down list.
Under Time-out (in minutes), verify “20 minutes or less” is selected.

If the "Use Cookies” mode is selected and Time-out (in minutes) is configured for “20 minutes or less”, this is not a finding.

Alternative method:
Click the site name.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
Verify the "cookieless" is set to "UseCookies".

If the "cookieless" is not set to "UseCookies", this is a finding.'
  desc 'fix', 'Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under the "ASP.NET" section, select "Session State".

Under "Cookie Settings", select the "Use Cookies" mode from the "Mode:" drop-down list.

Under “Time-out (in minutes), enter a value of “20 or less”.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15630r505357_chk'
  tag severity: 'medium'
  tag gid: 'V-214420'
  tag rid: 'SV-214420r508658_rule'
  tag stig_id: 'IISW-SV-000135'
  tag gtitle: 'SRG-APP-000223-WSR-000145'
  tag fix_id: 'F-15628r505358_fix'
  tag 'documentable'
  tag legacy: ['SV-91423', 'V-76727']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
