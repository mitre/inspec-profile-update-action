control 'SV-79485' do
  title 'The DBN-6300 must generate audit log events for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", that the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes"; the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console; and the items for any locally developed list of auditable events is checked.

Following this verification, process an account removal. Confirm the presence of a syslog message on the syslog server containing the date and time of this last logon.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that a logon has just occurred is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-65653r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64995'
  tag rid: 'SV-79485r1_rule'
  tag stig_id: 'DBNW-DM-000132'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-70935r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
