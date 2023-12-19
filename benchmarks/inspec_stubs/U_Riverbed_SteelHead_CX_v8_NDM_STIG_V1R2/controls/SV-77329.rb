control 'SV-77329' do
  title 'Riverbed Optimization System (RiOS) must automatically generate a log event for account creation events.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Verify that RiOS is configured to generate a log event for account creation events.

Create an account
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

Under Configuration, set minimum severity to Info'
  impact 0.3
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63633r1_chk'
  tag severity: 'low'
  tag gid: 'V-62839'
  tag rid: 'SV-77329r1_rule'
  tag stig_id: 'RICX-DM-000007'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-68757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
