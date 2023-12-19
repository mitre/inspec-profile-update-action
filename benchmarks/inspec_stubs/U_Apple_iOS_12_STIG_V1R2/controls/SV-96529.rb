control 'SV-96529' do
  title 'Apple iOS must implement the management setting: not allow use of Handoff.'
  desc "Handoff permits a user of an Apple iOS device to transition user activities from one device to another. Handoff passes sufficient information between the devices to describe the activity, but app data synchronization associated with the activity is handled though iCloud, which should be disabled on a compliant Apple iOS device. If a user associates both DoD and personal devices to the same Apple ID, the user may improperly reveal information about the nature of the user's activities on an unprotected device. Disabling Handoff mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Allow Handoff" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Allow Handoff" is unchecked.

Alternatively, verify the text "<key>allowActivityContinuation</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Handoff not allowed" is listed.

If "Allow Handoff" is checked in the Apple iOS management tool, "<key>allowActivityContinuation</key> <true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Handoff not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable continuation of activities among devices and workstations.'
  impact 0.3
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-81607r1_chk'
  tag severity: 'low'
  tag gid: 'V-81815'
  tag rid: 'SV-96529r1_rule'
  tag stig_id: 'AIOS-12-010900'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-88665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-7 a']
end
