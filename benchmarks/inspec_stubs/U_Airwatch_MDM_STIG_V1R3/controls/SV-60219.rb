control 'SV-60219' do
  title 'The AirWatch MDM Server must notify when it detects unauthorized changes to security configuration of managed mobile devices.'
  desc 'Incident response functions are intended to monitor, detect, and alarm on defined events occurring on the system or on the network.  A large part of their functionality is accurate and timely notification of events.  Notifications can be made more efficient by the creation of notification groups containing members who would be responding to a particular alarm or event.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server notifies when it detects unauthorized changes to security configuration of managed mobile devices. If the AirWatch MDM Server does not notify in this case, this is a finding.

To verify policies for detecting device changes via the Compliance Engine are set to notify properly, use the following procedure: 1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on applicable compliance policy to verify. (4) On Rules tab verify the correct rule set for the applicable policy to be applied. (5) Click "Next". (6) On Actions tab, verify the correct Action to take is set (for notification, first drop-down box should read "Notify", second should read "Send Email to Administrator", and third should list applicable email addresses). (7) On Assignment tab verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Use an AirWatch MDM Server that can perform required actions after receiving security related alerts.

To establish policies for the Compliance Engine, use the following procedure: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab, (3) select to match "All" or "Any" of the entered Rules, (4) in first drop-down box select applicable rule to be set, and (5) click "Next". (6) On Actions tab, (7) select "Notify" in first drop-down box, (8) select "Send Email to Administrator" in second drop-down box, and (9) enter in applicable email addresses for notification in "To:" box. (10) Click "Next". (11) On Assignment tab select device types, users, or groups to assign Policy to, and (12) click "Next". (13) View Summary for accuracy, and (14) click "Save and Assign".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50113r2_chk'
  tag severity: 'medium'
  tag gid: 'V-47347'
  tag rid: 'SV-60219r1_rule'
  tag stig_id: 'ARWA-01-000235'
  tag gtitle: 'SRG-APP-286-MDM-163-MDM'
  tag fix_id: 'F-51053r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001265']
  tag nist: ['SI-4 (6)']
end
