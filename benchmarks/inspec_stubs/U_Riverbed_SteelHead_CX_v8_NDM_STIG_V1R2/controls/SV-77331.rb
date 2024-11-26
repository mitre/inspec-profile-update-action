control 'SV-77331' do
  title 'Riverbed Optimization System (RiOS) must automatically log event for account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Verify that RiOS is configured to generate a log event for account creation events.

Create an account
Modify this user account
Navigate to the device Management Console, then
Navigate to:
Reports >> Diagnostics >> System Logs
Enter the account name into the filter and click Go
Delete the account that was created

If no event record for the user creation action exists in the event log, this is a finding.'
  desc 'fix', 'Configure RiOS to generate a log event for account creation events.

Navigate to the device Management Console, then
Navigate to:
Configure >> System Settings >> Logging

Under Configuration, set minimum severity to Info
Click "Save"

(The actual level for these messages is Notifications; however, other settings in this STIG call for the Info level and only one can be selected.)'
  impact 0.3
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63635r1_chk'
  tag severity: 'low'
  tag gid: 'V-62841'
  tag rid: 'SV-77331r1_rule'
  tag stig_id: 'RICX-DM-000008'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-68759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
