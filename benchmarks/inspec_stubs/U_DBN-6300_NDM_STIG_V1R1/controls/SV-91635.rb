control 'SV-91635' do
  title 'The DBN-6300 must produce audit log records containing information to establish the source of events.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event. The source may be a component, module, or process within the device or an external session, administrator, or device.

Location of events includes hardware components, device software module, processes within the device or external session, administrator ID, or device.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an auditable action. Confirm the presence of a syslog message on the syslog server containing information to establish the source of events.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message for the event does not contain information to establish the source of events, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76563r1_chk'
  tag severity: 'low'
  tag gid: 'V-76939'
  tag rid: 'SV-91635r1_rule'
  tag stig_id: 'DBNW-DM-000030'
  tag gtitle: 'SRG-APP-000098-NDM-000228'
  tag fix_id: 'F-83635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
