control 'SV-250975' do
  title 'Apple iOS/iPadOS 15 must disable "Allow USB drive access in Files app" if the Authorizing Official (AO) has not approved the use of DoD-approved USB storage drives with iOS/iPadOS devices.'
  desc 'Unauthorized use of USB storage drives could lead to the introduction of malware or unauthorized software into the DoD IT infrastructure and compromise of sensitive DoD information and systems.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This requirement is not applicable if the AO has approved the use of USB drives to load files to Apple devices. The approval must be in writing and include which USB storage devices are approved for use.

If the AO has not approved the use of USB drives to load files to Apple devices, use the following procedures to verify compliance:

This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Allow USB drive access in Files app" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow USB drive access in Files app" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Allow USB drive access in Files app" is not listed.

If "Allow USB drive access in Files app" is not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of USB drives to load files to Apple devices, install a configuration profile to disable "Allow USB drive access in Files app".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54410r802014_chk'
  tag severity: 'medium'
  tag gid: 'V-250975'
  tag rid: 'SV-250975r802016_rule'
  tag stig_id: 'AIOS-15-013300'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54364r802015_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
