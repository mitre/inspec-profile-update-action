control 'SV-91693' do
  title 'The DBN-6300 must audit the enforcement actions used to restrict access associated with changes to the device.'
  desc 'Without auditing the enforcement of access restrictions against changes to the device configuration, it will be difficult to identify attempted attacks, and an audit trail will not be available for forensic investigation for after-the-fact actions. 

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an account removal. Confirm the presence of a syslog message on the syslog server containing the date and time of this last logon.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that a logon just occurred is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76997'
  tag rid: 'SV-91693r1_rule'
  tag stig_id: 'DBNW-DM-000108'
  tag gtitle: 'SRG-APP-000381-NDM-000305'
  tag fix_id: 'F-83693r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
