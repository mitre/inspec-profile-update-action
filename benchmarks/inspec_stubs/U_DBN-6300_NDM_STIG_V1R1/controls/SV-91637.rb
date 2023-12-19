control 'SV-91637' do
  title 'The DBN-6300 must produce audit records that contain information to establish the outcome of the event.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an auditable action. Confirm the presence of a syslog message on the syslog server containing information to establish the outcome of the event.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message for the event does not contain information to establish the outcome of the event, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76565r1_chk'
  tag severity: 'low'
  tag gid: 'V-76941'
  tag rid: 'SV-91637r1_rule'
  tag stig_id: 'DBNW-DM-000031'
  tag gtitle: 'SRG-APP-000099-NDM-000229'
  tag fix_id: 'F-83637r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
