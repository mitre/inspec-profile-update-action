control 'SV-91179' do
  title 'The Akamai Luna Portal must generate audit records when successful/unsuccessful attempts to access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify that the portal is sending Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Search/filter for "Luna Control Center Event".
4. Click on the event name that meets the criteria above.
5. Verify that the applicable events are selected by clicking the "Settings" button.

If the Luna Control Center event notifications are not enabled, this is a finding.'
  desc 'fix', 'Enable Luna Event notifications:

1. Log in to the Luna Portal as an administrator.
2. Select Configure >> Alerts.
3. Click the "Create New Alert" button.
4. Select "Luna Control Center Event" and press the "Next" button.
5. Check the applicable boxes.
6. Proceed through the alert creation wizard, filling out the appropriate fields, and then click "Submit".'
  impact 0.3
  ref 'DPMS Target Akamai Edge Security NDM'
  tag check_id: 'C-76143r1_chk'
  tag severity: 'low'
  tag gid: 'V-76483'
  tag rid: 'SV-91179r1_rule'
  tag stig_id: 'AKSD-DM-000022'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-83161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
