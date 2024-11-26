control 'SV-91167' do
  title 'The Akamai Luna Portal must generate alerts that can be forwarded to the SAs and ISSO when accounts are modified.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Notification of account modification is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail that documents the modification of device administrator accounts and notifies the SAs and ISSO. Such a process greatly reduces the risk that accounts will be surreptitiously modified and provides logging that can be used for forensic purposes.

The network device must generate the alert. Notification may be done by a management server.'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click on "account modification".
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
  tag check_id: 'C-76131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76471'
  tag rid: 'SV-91167r1_rule'
  tag stig_id: 'AKSD-DM-000013'
  tag gtitle: 'SRG-APP-000292-NDM-000276'
  tag fix_id: 'F-83149r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001684']
  tag nist: ['AC-2 (4)']
end
