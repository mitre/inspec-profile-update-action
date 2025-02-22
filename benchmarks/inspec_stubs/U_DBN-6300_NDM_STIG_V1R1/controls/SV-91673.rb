control 'SV-91673' do
  title 'The DBN-6300 must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The DBN-6300 will reveal error messages only to authorized individuals (ISSO, ISSM, and SA). Only privileged users have visibility into any error messages. The audit log requires authorized users to log on to obtain visibility.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled."
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process any account function. Confirm the presence of a syslog message on the syslog server containing the information for whatever that account function represented.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information for the account action that took place is not present, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76603r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76977'
  tag rid: 'SV-91673r1_rule'
  tag stig_id: 'DBNW-DM-000077'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-83673r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
