control 'SV-91163' do
  title 'The Akamai Luna Portal must automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click the "Settings" button and click on "Properties" tab.
5. Verify that the following setting is selected: "Manage - Manage Users".

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable account removal alerting:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click the "Settings" button and click on "Properties" tab.
5. Select "Manage - Manage Users".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76127r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76467'
  tag rid: 'SV-91163r1_rule'
  tag stig_id: 'AKSD-DM-000011'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-83145r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
