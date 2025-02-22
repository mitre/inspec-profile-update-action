control 'SV-91627' do
  title 'The DBN-6300 must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories can be checked in accordance with the role assigned. For an administrator, the admin role should allow all categories to be checked for Audit Log, Syslog, and Audit Console.

Log off and log on to the system again. Examine the message at the syslog server.

If there is no message, or no information in the message containing data showing the logon, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.3
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76555r1_chk'
  tag severity: 'low'
  tag gid: 'V-76931'
  tag rid: 'SV-91627r1_rule'
  tag stig_id: 'DBNW-DM-000026'
  tag gtitle: 'SRG-APP-000092-NDM-000224'
  tag fix_id: 'F-83627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
