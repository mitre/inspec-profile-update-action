control 'SV-60209' do
  title 'The AirWatch MDM Server must employ automated mechanisms to respond to unauthorized changes to the security policy or AirWatch MDM Server agent on managed mobile devices.'
  desc 'Uncoordinated or incorrect configuration changes to the AirWatch MDM Server managed components can potentially lead to compromises.  Without automated mechanisms to respond to changes, changes can go unnoticed for a significant amount of time which could result in compromise.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server can employ automated mechanisms to respond to unauthorized changes to the security policy or AirWatch MDM Server agent on managed mobile devices. If this function is not present, this is a finding.

To verify policies for the Compliance Engine, use the following procedure: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on applicable compliance policy. On Rules tab, verify the correct rule set for the applicable policy to be applied. (4) On Actions tab, verify the correct Action type to take Actionable Result is set. (5) On Assignment verify correct device types, users, or groups are assigned.

(Note: for "jailbroken" or "rooted device" detection, verify "Compromised Status" and "Is Compromised" is selected on Rules tab.'
  desc 'fix', 'Configure the AirWatch MDM Server to automatically respond to unauthorized changes to the security policy or AirWatch MDM Server agent on managed mobile devices.

To establish policies for the Compliance Engine, use the following procedure: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab select the following: (1a) to Match "All" or "Any" of the entered Rules, (2a) choose deviation to detect on devices, and (3a) click "Next". (3) On Actions tab, select the following: (a) choose Action type to take (command), and (b) Actionable Result, and (c) click "Next". (4) On Assignment tab select device types, users, or groups to assign Policy to, and (5) click "Next". (6) View Summary for accuracy, and (7) click "Save and Assign".

(Note: for "jailbroken" or "rooted device" detection, select "Compromised Status" and "Is Compromised" on Rules tab.'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50103r3_chk'
  tag severity: 'medium'
  tag gid: 'V-47337'
  tag rid: 'SV-60209r1_rule'
  tag stig_id: 'ARWA-02-000190'
  tag gtitle: 'SRG-APP-138-MDM-152-MDM'
  tag fix_id: 'F-51043r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000374']
  tag nist: ['CM-6 (2)']
end
