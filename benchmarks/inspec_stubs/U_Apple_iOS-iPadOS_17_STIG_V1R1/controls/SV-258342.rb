control 'SV-258342' do
  title 'Apple iOS/iPadOS 17 must implement the management setting: not allow use of Handoff.'
  desc "Handoff permits a user of an iPhone and iPad to transition user activities from one device to another. Handoff passes sufficient information between the devices to describe the activity, but app data synchronization associated with the activity is handled though iCloud, which should be disabled on a compliant iPhone and iPad. If a user associates both DOD and personal devices to the same Apple ID, the user may improperly reveal information about the nature of the user's activities on an unprotected device. Disabling Handoff mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #47"
  desc 'check', 'Review configuration settings to confirm "Allow Handoff" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Allow Handoff" is unchecked.

Alternatively, verify the text "<key>allowActivityContinuation</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Handoff not allowed" is listed.

If "Allow Handoff" is checked in the Apple iOS/iPadOS management tool, "<key>allowActivityContinuation</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Handoff not allowed", this is a finding.

This requirement will become "Supervised only" in a future iOS/iPadOS release.'
  desc 'fix', 'Install a configuration profile to disable continuation of activities among devices and workstations.

This requirement will become "Supervised only" in a future iOS/iPadOS release.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62083r927707_chk'
  tag severity: 'low'
  tag gid: 'V-258342'
  tag rid: 'SV-258342r935481_rule'
  tag stig_id: 'AIOS-17-010800'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62007r927708_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
end
