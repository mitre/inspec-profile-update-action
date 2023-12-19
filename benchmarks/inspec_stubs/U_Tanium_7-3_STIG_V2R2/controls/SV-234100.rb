control 'SV-234100' do
  title 'A Tanium connector must be configured to send log data to an external audit log reduction capable system.'
  desc 'While the Tanium Server records audit log entries to the Tanium SQL database, retrieval and aggregation of log data through the Tanium console is not efficient.

The Tanium Connect module allows for SIEM connectors in order to facilitate forensic data retrieval and aggregation efficiently. Consult documentation at https://docs.tanium.com/connect/connect/index.html for supported Connections.'
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

Consult documentation located at https://docs.tanium.com/connect/connect/index.html for reference on configuring other applicable SIEM connections.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37285r610800_chk'
  tag severity: 'medium'
  tag gid: 'V-234100'
  tag rid: 'SV-234100r612749_rule'
  tag stig_id: 'TANS-SV-000029'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-37250r610801_fix'
  tag 'documentable'
  tag legacy: ['SV-102273', 'V-92171']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
