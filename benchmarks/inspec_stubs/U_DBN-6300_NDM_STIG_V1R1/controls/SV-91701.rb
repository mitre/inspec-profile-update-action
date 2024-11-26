control 'SV-91701' do
  title 'The DBN-6300 must generate audit records when successful/unsuccessful attempts to delete administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an account administrator privilege modification. Confirm the presence of a syslog message on the syslog server containing the deletion of account administrator privileges.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the deletion of account administrator privileges is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes".

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".

Verify that the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If any of the Configuration Categories are not checked, cycle the top buttons until every category is completely checked.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-77005'
  tag rid: 'SV-91701r1_rule'
  tag stig_id: 'DBNW-DM-000122'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-83701r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
