control 'SV-91175' do
  title 'The Akamai Luna Portal must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify that the portal is sending the expected Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click on "execution of privileged functions".
5. Verify that the following settings are selected by clicking the "Settings" button:
"Manage - Manage Users".

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Click the "Create New Alert" button.
4. Select "Luna Control Center Event" and press the "Next" button.
5. Check the boxes for applicable alerts.
6. Proceed through the alert creation wizard, filling out the appropriate fields, and then click "Submit".'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76479'
  tag rid: 'SV-91175r1_rule'
  tag stig_id: 'AKSD-DM-000018'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-83157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
