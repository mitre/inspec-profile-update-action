control 'SV-250961' do
  title 'Apple iOS/iPadOS 15 must implement the management setting: force Apple Watch wrist detection.'
  desc 'Because Apple Watch is a personal device, it is key that any sensitive DoD data displayed on the Apple Watch cannot be viewed when the watch is not in the immediate possession of the user. This control ensures the Apple Watch screen locks when the user takes the watch off, thereby protecting sensitive DoD data from possible exposure.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Force Apple Watch wrist detection" is enabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the Apple iOS/iPadOS management tool, verify "Wrist detection enforced on Apple Watch" is enforced.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the Apple iOS/iPadOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Wrist detection enforced on Apple Watch" is listed.

If "Wrist detection enforced on Apple Watch" is not enforced in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "Wrist detection enforced on Apple Watch", this is a finding.'
  desc 'fix', 'Install a configuration profile to force Apple Watch wrist detection.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54396r801972_chk'
  tag severity: 'low'
  tag gid: 'V-250961'
  tag rid: 'SV-250961r801974_rule'
  tag stig_id: 'AIOS-15-011800'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54350r801973_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
