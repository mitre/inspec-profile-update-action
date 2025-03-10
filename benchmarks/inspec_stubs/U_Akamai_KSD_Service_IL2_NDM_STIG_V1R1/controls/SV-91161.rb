control 'SV-91161' do
  title 'The Akamai Luna Portal must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click the "Settings" button and click on "Properties" tab.
5. Verify that the following setting is selected: "Manage - Manage Users".

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable account modification alerting:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click the "Settings" button and click on "Properties" tab.
5. Select "Manage - Manage Users".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76125r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76465'
  tag rid: 'SV-91161r1_rule'
  tag stig_id: 'AKSD-DM-000009'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-83143r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
