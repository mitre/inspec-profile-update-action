control 'SV-219395' do
  title 'Apple iOS/iPadOS must disable Allow USB drive access in Files access if the AO has not approved the use of DoD approved USB storage drives with iOS/iPadOS devices.'
  desc 'Unauthorized use of USB storage drives could lead to the introduction of malware or unauthorized software into the DoD IT infrastructure and compromise of sensitive DoD information and systems.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This requirement is not applicable if the AO has approved the use of USB drives to load files to Apple devices. The approval must be in writing and include which USB storage devices are approved for use.

If the AO has not approved the use of USB drives to load files to Apple devices, use the following procedures for verifying compliance:

This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is Supervised by the MDM, review configuration settings to confirm "Allow USB drive access in Files access" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow USB drive access in Files access" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Allow USB drive access in Files access" is not listed.

If "Allow USB drive access in Files access" is not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of USB drives to load files to Apple devices, install a configuration profile to disable "Allow USB drive access in Files access".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21120r547694_chk'
  tag severity: 'medium'
  tag gid: 'V-219395'
  tag rid: 'SV-219395r604137_rule'
  tag stig_id: 'AIOS-13-013800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21119r547695_fix'
  tag 'documentable'
  tag legacy: ['SV-106623', 'V-97519']
  tag cci: ['CCI-000097', 'CCI-000370', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 (1)', 'CM-6 b']
end
