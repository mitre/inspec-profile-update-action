control 'SV-91715' do
  title 'The DBN-6300 must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create a new account.

Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of accounts and notifies administrators and ISSOs. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes"; the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console; and the items for any locally developed list of auditable events is checked.

Following this verification, process any type of account management activity. Confirm the presence of a syslog message on the syslog server containing the information regarding the account management function that was used.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that a logon has just occurred is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.7
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76645r1_chk'
  tag severity: 'high'
  tag gid: 'V-77019'
  tag rid: 'SV-91715r1_rule'
  tag stig_id: 'DBNW-DM-000142'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-83715r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
