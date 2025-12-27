control 'SV-259193' do
  title 'Apple iOS/iPadOS 17 must disable "Allow USB drive access in Files app" if the authorizing official (AO) has not approved the use of DOD-approved USB storage drives with iOS/iPadOS devices.'
  desc 'Unauthorized use of USB storage drives could lead to the introduction of malware or unauthorized software into the DOD IT infrastructure and compromise of sensitive DOD information and systems.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This requirement is not applicable if the AO has approved the use of USB drives to load files to Apple devices. The approval must be in writing and include which USB storage devices are approved for use.

If the AO has not approved the use of USB drives to load files to Apple devices, use the following procedures to verify compliance.

This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Allow USB drive access in Files app" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow USB drive access in Files app" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "USB drives not accessible in Files app" is listed.

If "Allow USB drive access in Files app" is not disabled in the management tool and "USB drives not accessible in Files app" is not listed in the Restrictions profile on the Apple device, this is a finding.'
  desc 'fix', 'If the AO has not approved the use of USB drives to load files to Apple devices, install a configuration profile to disable "Allow USB drive access in Files app".'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62933r935547_chk'
  tag severity: 'medium'
  tag gid: 'V-259193'
  tag rid: 'SV-259193r935549_rule'
  tag stig_id: 'AIOS-17-013300'
  tag gtitle: 'PP-MDF-333240'
  tag fix_id: 'F-62842r935548_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
