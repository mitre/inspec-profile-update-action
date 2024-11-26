control 'SV-218735' do
  title 'The IIS 10.0 website session state must be enabled.'
  desc "When the session information is stored on the client, the session ID, along with the user authorization and identity information, is sent along with each client request and is either stored in a cookie, embedded in the uniform resource locator (URL), or placed in a hidden field on the displayed form. Each of these offers advantages and disadvantages. The biggest disadvantage to all three is the hijacking of a session along with all of the user's credentials.

When the user authorization and identity information is stored on the server in a protected and encrypted database, the communication between the client and web server will only send the session identifier, and the server can then retrieve user credentials for the session when needed. If, during transmission, the session were to be hijacked, the user's credentials would not be compromised.

ASP.NET provides a session state, which is available as the HttpSessionState class, as a method of storing session-specific information that is visible only within the session. ASP.NET session state identifies requests from the same browser during a limited time window as a session, and provides the ability to persist variable values for the duration of that session."
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Under the "ASP.NET" section, select "Session State".

Under "Session State Mode Settings", verify the "In Process" mode is selected.

If the "Session State Mode Settings" is set to "In Process", this is not a finding.

Alternative method:

Click the site name.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".

Verify the "mode" reflects "InProc".

If the "mode" is not set to "InProc", this is a finding.

If the system being reviewed is part of a Web Farm, interview the System Administrator to ensure Session State Tracking is enabled via a SQL server, or other means. If Session State Tracking is enabled on the Web Farm, this is not a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 10.0 web server:

Open the IIS 10.0 Manager.

Click the site name.

Under the "ASP.NET" section, select "Session State".

Under "Session State Mode Settings", verify the "In Process" mode is selected.

Select "Apply" from the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Site'
  tag check_id: 'C-20208r311103_chk'
  tag severity: 'medium'
  tag gid: 'V-218735'
  tag rid: 'SV-218735r558649_rule'
  tag stig_id: 'IIST-SI-000201'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-20206r311104_fix'
  tag 'documentable'
  tag legacy: ['SV-109295', 'V-100191']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
