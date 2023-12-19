control 'SV-91625' do
  title 'The DBN-6300 must generate log records when successful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).

It is not possible to perform unsuccessful commands in the UI web management interface since it is a GUI interface. Unauthorized menu items/commands are not visible.'
  desc 'check', 'Navigate to Settings >> Advanced >> Syslog.

Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected.

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and that the Audit Configuration Categories can be checked in accordance with the role assigned. For an administrator, the admin role should allow all categories to be checked for Audit Log, Syslog, and Audit Console.

Log off, log on again, and attempt to repeat the process logged on as a "lesser" user that does not have privileges to configure audit.

Attempt to modify the audit log categories. This should fail.

Following this verification, if it is possible for a non-privileged user with no audit log modification privileges to modify log functions, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. Also configure the DBN-6300 to include audit records in the syslog message feed.

Navigate to Settings >> Advanced >> Syslog.

Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable".

Navigate to Settings >> Advanced >> Audit Log.

Verify that the Audit Syslog, "Use System Syslog" button is set to "Yes" and the Audit Configuration Categories are all checked for Audit Log, Syslog, and Audit Console.

If the "Use System Syslog" button is not set to "Yes", press the "Yes" button.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76553r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76929'
  tag rid: 'SV-91625r1_rule'
  tag stig_id: 'DBNW-DM-000025'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-83625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
