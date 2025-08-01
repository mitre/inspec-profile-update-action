control 'SV-77347' do
  title 'Riverbed Optimization System (RiOS) must generate a log event when privileged functions are executed.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify the device generates a log event when commands are executed.

Navigate to the device Management Console
Navigate to Configure >> System Settings >> Logging

Under Logging Configurations, verify Minimum Severity is set to Info

If the Standard Mandatory DoD Notice and Consent Banner does not exist on this page, this is a finding.'
  desc 'fix', 'Since all commands on the device are privileged commands, the following command ensures execution of commands are sent to the Syslog Server. 

Navigate to the Device Management Console
Navigate to Configure >> System Settings >> Logging

Under "Remote Log Servers", click "Add a New Log Server"
Enter the server IP address

Under Logging Configurations >> Minimum Severity, select "Info"

Click "Add"

Add an IP and Minimum Severity level for the backup Syslog server.'
  impact 0.3
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63651r1_chk'
  tag severity: 'low'
  tag gid: 'V-62857'
  tag rid: 'SV-77347r1_rule'
  tag stig_id: 'RICX-DM-000023'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-68775r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
