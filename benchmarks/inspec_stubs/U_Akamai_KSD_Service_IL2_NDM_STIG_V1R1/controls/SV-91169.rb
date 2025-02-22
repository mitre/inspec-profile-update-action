control 'SV-91169' do
  title 'The Akamai Luna Portal must generate alerts that can be forwarded to the SAs and ISSO when accounts are removed.'
  desc 'When application accounts are removed, administrator accessibility is affected. Accounts are used for identifying individual device administrators or for identifying the device processes themselves. 

In order to detect and respond to events that affect administrator accessibility and device processing, devices must audit account removal actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that device accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click on "account removal".
5. Verify that the following settings are selected by clicking the "Settings" button:
"Manage - Manage Users".

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Click the "Create New Alert" button.
4. Select "Luna Control Center Event" and press the "Next" button.
5. Check the box that reads "Manage - Manage Users".
6. Proceed through the alert creation wizard, filling out the appropriate fields, and then click "Submit".

Alternatively, custom notifications can be created by using the event manager API at https://developer.akamai.com/api/luna/events/overview.html.'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76473'
  tag rid: 'SV-91169r1_rule'
  tag stig_id: 'AKSD-DM-000015'
  tag gtitle: 'SRG-APP-000294-NDM-000278'
  tag fix_id: 'F-83151r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001686']
  tag nist: ['AC-2 (4)']
end
