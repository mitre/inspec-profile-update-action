control 'SV-60223' do
  title 'The AirWatch MDM Server device integrity validation component must include the capability to notify an organization-defined list of response personnel who are identified by name and/or by role notifications of suspicious events.'
  desc 'Integrity checking applications are by their nature, designed to monitor and detect defined events occurring on the system. When the integrity checking mechanism finds an anomaly, it must notify personnel in order to ensure the proper action is taken based upon the integrity issues found. If notification is not performed, the issue may continue or worsen to allow intruders into the system.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure the AirWatch MDM Server device integrity validation component includes the capability to notify an organization-defined list of response personnel who are identified by name and/or by role notifications of suspicious events.  If this function is not configured, this is a finding.

To verify policies for detecting device changes via the Compliance Engine are set to notify properly, use the following procedure: (1) click "Menu" on top tool bar, (2) click "Compliance" under "Profiles and Policies" heading, and (3) click on applicable compliance policy to verify on Rules tab the correct rule set for the applicable policy to be applied.  (4) Click "Next".  (5) On Actions tab, verify the correct Action to take is set (for notification, first drop-down box should read "Notify", second should read "Send Email to Administrator", and third should list applicable email addresses).  (6) On Assignment tab, verify correct device types, users, or groups are assigned.'
  desc 'fix', 'Configure the AirWatch MDM Server device integrity validation component to provide the capability to notify an organization-defined list of response personnel who are identified by name and/or by role notifications of suspicious events.

To establish policies for the Compliance Engine, use the following procedure: (1) click "Add" from the top tool bar, and (2) click "Compliance Policy". On Rules tab, (3) select to match "All" or "Any" of the entered Rules, (4) in first drop-down box, select applicable rule to be set, and (5) click "Next". (6) On Actions tab, (7) select "Notify" in first drop-down box, (8) select "Send Email to Administrator" in second drop-down box, and (9) enter in applicable email addresses for notification in "To:" box. (10) Click "Next". (11) On Assignment tab select device types, users, or groups to assign Policy to, and (12) click "Next". (13) View Summary for accuracy, and (14) click "Save and Assign".'
  impact 0.5
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50117r1_chk'
  tag severity: 'medium'
  tag gid: 'V-47351'
  tag rid: 'SV-60223r1_rule'
  tag stig_id: 'ARWA-01-000237'
  tag gtitle: 'SRG-APP-286-MDM-174-MDIS'
  tag fix_id: 'F-51057r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001266']
  tag nist: ['SI-4 (7) (a)']
end
