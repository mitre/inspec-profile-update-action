control 'SV-93141' do
  title 'Apple iOS must implement the management setting: force Apple Watch wrist detection.'
  desc 'Because Apple Watch is a personal device, it is key that any sensitive DoD data displayed on the Apple Watch not be viewable when the watch is not in the immediate possession of the user. This control ensures the Apple Watch screen locks when the user takes the watch off, thereby protecting sensitive DoD data from possible exposure.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review configuration settings to confirm "Force Apple Watch wrist detection" is enabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Wrist detection enforced on Apple Watch" is enforced.

On the Apple iOS device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the Apple iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Wrist detection enforced on Apple Watch" is listed.

If "Wrist detection enforced on Apple Watch" is not enforced in the Apple iOS management tool or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Wrist detection enforced on Apple Watch", this is a finding.'
  desc 'fix', 'Install a configuration profile to force Apple Watch wrist detection.'
  impact 0.3
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77997r1_chk'
  tag severity: 'low'
  tag gid: 'V-78435'
  tag rid: 'SV-93141r1_rule'
  tag stig_id: 'AIOS-11-012500'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-85167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
