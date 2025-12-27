control 'SV-91629' do
  title 'The DBN-6300 must produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console. 

If the DBN-6300 is not connected to the syslog server, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76557r1_chk'
  tag severity: 'low'
  tag gid: 'V-76933'
  tag rid: 'SV-91629r1_rule'
  tag stig_id: 'DBNW-DM-000027'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-83629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
