control 'SV-91165' do
  title 'The Akamai Luna Portal must generate alerts that can be forwarded to the SAs and ISSO when accounts are created.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the creation of accounts and notifies the SAs and ISSO. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

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
5. Check the box that reads "Manage - Manage Users".
6. Proceed through the alert creation wizard, filling out the appropriate fields, and then click "Submit".

Alternatively, custom notifications can be created by using the event manager API at https://developer.akamai.com/api/luna/events/overview.html.'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76129r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76469'
  tag rid: 'SV-91165r1_rule'
  tag stig_id: 'AKSD-DM-000012'
  tag gtitle: 'SRG-APP-000291-NDM-000275'
  tag fix_id: 'F-83147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
