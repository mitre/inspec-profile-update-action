control 'SV-91173' do
  title 'The Akamai Luna Portal must notify the SAs and ISSO when accounts are created, or enabled when previously disabled.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies the SAs and ISSO. Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes.

In order to detect and respond to events that affect network administrator accessibility and device processing, network devices must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event.'
  desc 'check', 'Verify that the portal is sending the expected Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click on "account creation".
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
  tag check_id: 'C-76137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76477'
  tag rid: 'SV-91173r1_rule'
  tag stig_id: 'AKSD-DM-000017'
  tag gtitle: 'SRG-APP-000320-NDM-000284'
  tag fix_id: 'F-83155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
