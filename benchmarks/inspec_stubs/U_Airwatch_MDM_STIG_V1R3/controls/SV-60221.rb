control 'SV-60221' do
  title 'The AirWatch MDM Server must perform required actions when a security related alert is received.'
  desc 'Incident response functions are intended to monitor, detect, and alarm on defined events occurring on the system or on the network.  A large part of their functionality is accurate and timely notification of events.  Notifications can be made more efficient by the creation of notification groups containing members who would be responding to a particular alarm or event.  Types of actions the AirWatch MDM Server must be able to perform after a security alert include:  log the alert, send email to a system administrator, wipe the managed mobile device, lock the mobile device account on the AirWatch MDM Server, disable the security container, wipe the security container, and delete any unapproved application.  Security alerts include any alert from the MDIS or MAM component of the AirWatch MDM Server.'
  desc 'check', 'Review the AirWatch MDM Server configuration to determine if it has the capability to perform required actions after receiving a security related alert. If the AirWatch MDM Server cannot perform required actions after receiving a security related alert, this is a finding.

This requirement is met by setting appropriate Actions to be taken by the automated Compliance Engine component:

To verify policies for detecting device changes via the Compliance Engine are set to notify properly, use the following procedure: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on applicable compliance policy to verify. (4) On Rules tab verify the correct rule set for the applicable policy to be applied. (5) Click "Next". (6) On Actions tab, verify the correct Action to take is set (for notification, first drop-down box should read "Notify", second should read "Send Email to Administrator", and third should list applicable email addresses). (7) On Assignment tab verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Use an AirWatch MDM Server that can perform required actions after receiving security related alerts.

To establish policies for the Compliance Engine, use the following procedure: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab, (3) select to match "All" or "Any" of the entered Rules, (4) in first drop-down box select applicable rule to be set, and (5) click "Next". (6) On Actions tab, select appropriate action to take. (7) Click "Next". (8) On Assignment tab select device types, users, or groups to assign Policy to, and (9) click "Next". (10) View Summary for accuracy, and (11) click "Save and Assign".'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50115r2_chk'
  tag severity: 'high'
  tag gid: 'V-47349'
  tag rid: 'SV-60221r1_rule'
  tag stig_id: 'ARWA-01-000236'
  tag gtitle: 'SRG-APP-286-MDM-164-MDM'
  tag fix_id: 'F-51055r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001265']
  tag nist: ['SI-4 (6)']
end
