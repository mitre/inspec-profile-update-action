control 'SV-234065' do
  title 'The Tanium enterprise audit log reduction option must be configured to provide alerts based off Tanium audit data.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Tanium Sources listed.

If an "Audit Log" source does not exist, this is a finding.

Select the "Audit Log" source.

Select the audit connection found in the lower half of the screen.

Verify the "Destination Type" is a SIEM tool.

If the "Destination Type" is not a SIEM tool, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click "Create Connection".

In the Source and Destination Section, select "Audit Log" as the Event Source from the drop-down menu.

In the "Destination" section, select "Socket Receiver" from the drop-down menu.

Enter "Destination Name".

Enter "Host".

Enter "Network Protocol".

Enter "Port".

Consult documentation located at https://docs.tanium.com/connect/connect/index.html for reference on configuring other applicable SIEM connections.

Work with the SIEM administrator to configure alerts based on audit failures.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37250r610695_chk'
  tag severity: 'medium'
  tag gid: 'V-234065'
  tag rid: 'SV-234065r612749_rule'
  tag stig_id: 'TANS-CN-000023'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-37215r610696_fix'
  tag 'documentable'
  tag legacy: ['SV-102203', 'V-92101']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
