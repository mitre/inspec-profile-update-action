control 'SV-254637' do
  title 'Apple iOS/iPadOS 16 must disable "Allow network drive access in Files access".'
  desc 'Allowing network drive access by the Files app could lead to the introduction of malware or unauthorized software into the DoD IT infrastructure and compromise of sensitive DoD information and systems.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow network drive access in Files access" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Network drives not accessible in Files app" is listed.

If "Allow network drive access in Files access" is not disabled in the management tool and "Network drives not accessible in Files app" is not listed in Profile Restrictions on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "Allow network drive access in Files access".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58248r862165_chk'
  tag severity: 'medium'
  tag gid: 'V-254637'
  tag rid: 'SV-254637r862228_rule'
  tag stig_id: 'AIOS-16-014300'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58194r862166_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
