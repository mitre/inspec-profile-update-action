control 'SV-91159' do
  title 'The Akamai Luna Portal must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click the "Settings" button and click on "Properties" tab.
5. Verify that the following setting is selected:  "Manage - Manage Users".

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable account creation alerting:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click the "Settings" button and click on "Properties" tab.
5. Select "Manage - Manage Users".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76463'
  tag rid: 'SV-91159r1_rule'
  tag stig_id: 'AKSD-DM-000008'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-83141r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
