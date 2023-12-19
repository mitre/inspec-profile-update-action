control 'SV-77335' do
  title 'Riverbed Optimization System (RiOS) must automatically generate a log event for account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Verify that RiOS is configured to generate a log event for account creation events.

Create an account
To disable an account
Navigate to the device Management Console, then
Navigate to:
Configure >> Security >> User >> Permissions
Select the account to be removed 
Click Remove Selected Account

Navigate to the device Management Console, then
Navigate to:
Reports >> Diagnostics >> System Logs
Enter the account name into the filter and click "Go"
Delete the account that was created.

If no event record for the user removal action exists in the event log, this is a finding.'
  desc 'fix', 'Configure RiOS to generate a log event for account disabling actions.

Navigate to the device Management Console, then
Navigate to:
Configure >> System Settings >> Logging

Under Configuration, set minimum severity to Info 
Click "Save"

Under Configuration, set minimum severity to Info.'
  impact 0.3
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63639r1_chk'
  tag severity: 'low'
  tag gid: 'V-62845'
  tag rid: 'SV-77335r1_rule'
  tag stig_id: 'RICX-DM-000010'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-68763r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
