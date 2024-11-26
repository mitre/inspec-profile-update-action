control 'SV-91645' do
  title 'The DBN-6300 must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to ensure that, in the event of a catastrophic system failure, the audit records will be retained. Backup of audit records helps to ensure that a compromise of the information system being audited does not also result in a compromise of the audit records.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process a logon. Confirm the presence of a syslog message on the syslog server containing the date and time of this last logon.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that a logon had just occurred is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76573r1_chk'
  tag severity: 'low'
  tag gid: 'V-76949'
  tag rid: 'SV-91645r1_rule'
  tag stig_id: 'DBNW-DM-000043'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-83645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
