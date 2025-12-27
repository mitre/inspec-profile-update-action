control 'SV-91631' do
  title 'The DBN-6300 must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an auditable action. Confirm the presence of a syslog message on the syslog server containing date and time information for when the event occurred.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message for the event does not contain date and time information, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76559r1_chk'
  tag severity: 'low'
  tag gid: 'V-76935'
  tag rid: 'SV-91631r1_rule'
  tag stig_id: 'DBNW-DM-000028'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-83631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
