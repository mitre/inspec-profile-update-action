control 'SV-214462' do
  title 'The IIS 8.5 website must generate unique session identifiers that cannot be reliably reproduced.'
  desc 'Communication between a client and the web server is done using the HTTP protocol, but HTTP is a stateless protocol. In order to maintain a connection or session, a web server will generate a session identifier (ID) for each client session when the session is initiated. The session ID allows the web server to track a user session and, in many cases, the user, if the user previously logged into a hosted application.

By being able to guess session IDs, an attacker can easily perform a man-in-the-middle attack. To truly generate random session identifiers that cannot be reproduced, the web server session ID generator, when used twice with the same input criteria, must generate an unrelated random ID.

The session ID generator also needs to be a FIPS 140-2-approved generator.'
  desc 'check', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name.

Under the "ASP.NET" section, select "Session State".

Under "Session State" Mode Settings, verify the "In Process" mode is selected.

If the "In Process" mode is selected, this is not a finding.

Alternative method:

Click the site name.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".

Verify the "mode" reflects "InProc".

If the "mode" is not set to "InProc", this is a finding.

If the system being reviewed is part of a Web Farm, interview the System Administrator to ensure Session State Tracking is enabled via a SQL server, or other means.  If Session State Tracking is enabled on the Web Farm, this is not a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Click the site name.

Under the ASP.NET section, select "Session State".

Under "Session State" Mode Settings, select the "In Process" mode.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15671r505315_chk'
  tag severity: 'medium'
  tag gid: 'V-214462'
  tag rid: 'SV-214462r508659_rule'
  tag stig_id: 'IISW-SI-000223'
  tag gtitle: 'SRG-APP-000224-WSR-000136'
  tag fix_id: 'F-15669r505316_fix'
  tag 'documentable'
  tag legacy: ['SV-91509', 'V-76813']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
