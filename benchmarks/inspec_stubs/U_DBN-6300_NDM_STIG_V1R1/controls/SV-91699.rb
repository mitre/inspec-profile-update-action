control 'SV-91699' do
  title 'The DBN-6300 must generate audit records when successful/unsuccessful attempts to modify administrator privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the network device (e.g., module or policy filter).

Administrative roles cannot be changed on the device console; thus, this only applies to the User Interface (UI) web management tool. 

All account activities (creation, modification, disabling, and removal, and other account activities, including successful/unsuccessful attempts to modify administrator privileges) on the DBN-6300 are written out to an audit log. This log carries a wealth of information that provides valuable forensic help, including the origin IP and port and destination and port where the event occurred, as well as the type of event and when it occurred. This data is all used to help establish the identity of any individual or process associated with the event. This can be verified by accessing the audit logs remotely by downloading the System State Report.

With the DBN-6300, audit records are automatically backed up on a real-time basis via syslog when enabled.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server.

Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

Following this verification, process an account administrator privilege modification. Confirm the presence of a syslog message on the syslog server containing the account administrator privilege modification.

If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected but the message containing the information that an account administrator privilege modification has occurred is not there, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76629r1_chk'
  tag severity: 'medium'
  tag gid: 'V-77003'
  tag rid: 'SV-91699r1_rule'
  tag stig_id: 'DBNW-DM-000121'
  tag gtitle: 'SRG-APP-000495-NDM-000318'
  tag fix_id: 'F-83699r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
