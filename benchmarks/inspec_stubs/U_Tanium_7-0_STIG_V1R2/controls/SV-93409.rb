control 'SV-93409' do
  title 'A Tanium connector must be configured to send log data to an external audit log reduction-capable system and provide alerts.'
  desc 'While the Tanium Server records audit log entries to the Tanium SQL database, retrieval and aggregation of log data through the Tanium console is not efficient.

The Tanium Connect module allows for SIEM connectors in order to facilitate forensic data retrieval and aggregation efficiently. Consult documentation at https://docs.tanium.com/connect/connect/index.html for supported connections.

It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Tanium Sources listed.

If an "Audit Log" Source does not exist, this is a finding.

Select the "Audit Log" source.

Select the audit connection found in the lower half of the screen.

Verify the "Destination Type" is a SIEM tool.

If the "Destination Type" is not a SIEM tool, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "Create Connection".

In the Source and Destination section, select "Audit Log" as the Event Source from the drop-down menu.

In the Destination section, select "Socket Receiver" from the drop-down menu.

Enter "Destination Name", "Host", "Network Protocol", and "Port".

Consult documentation located at https://docs.tanium.com/connect/connect/index.html for reference on configuring other applicable SIEM connections.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78703'
  tag rid: 'SV-93409r1_rule'
  tag stig_id: 'TANS-SV-000029'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-85439r1_fix'
  tag satisfies: ['SRG-APP-000358', 'SRG-APP-000360']
  tag 'documentable'
  tag cci: ['CCI-001851', 'CCI-001858']
  tag nist: ['AU-4 (1)', 'AU-5 (2)']
end
