control 'SV-91713' do
  title 'The DBN-6300 must off-load audit records onto a different system or media than the system being audited.'
  desc 'Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

The intent of this control is to ensure that log information does not get overwritten if the limited log storage capacity is reached and also to protect the log records in general if the system/component being logged is compromised (hence the notion of off-loading onto a different system or media) but the intent is not to hold the information in more than one or multiple locations.

This requirement is intended to address the primary repository, which is on the centralized Syslog server. This requirement is only applicable to the server used as the Syslog server.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
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
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76643r1_chk'
  tag severity: 'medium'
  tag gid: 'V-77017'
  tag rid: 'SV-91713r1_rule'
  tag stig_id: 'DBNW-DM-000128'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-83713r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
