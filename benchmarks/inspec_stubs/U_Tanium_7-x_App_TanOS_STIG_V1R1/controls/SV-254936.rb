control 'SV-254936' do
  title 'The Tanium application must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Review the configured Tanium Sources listed.

If an "Audit Log" source does not exist, this is a finding.

5. Select the "Audit Log" source.

6. Select the audit connection found in the lower half of the screen.

7. Verify the "Destination Type" is a SIEM tool.

If the "Destination Type" is not a SIEM tool, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Modules" on the top navigation banner.

3. Click "Connect".

4. Click "Create Connection".

5. In the Configuration section, select "Tanium Audit Source" as the Event Source from the "Source" drop-down menu.

6. In the "Destination" section, select "Socket Receiver" from the drop-down menu.

7. Enter "Destination Name".

8. Enter "Host".

9. Enter "Network Protocol".

10. Enter "Port".

11. Click "Save".

Consult documentation located at https://docs.tanium.com/connect/connect/siem.html#siem for reference on configuring other applicable SIEM connections.

Work with the SIEM administrator to configure alerts based on audit failures.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58549r867706_chk'
  tag severity: 'medium'
  tag gid: 'V-254936'
  tag rid: 'SV-254936r870363_rule'
  tag stig_id: 'TANS-AP-000875'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-58493r870363_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
