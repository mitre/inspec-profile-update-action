control 'SV-219390' do
  title 'Apple iOS/iPadOS must disable allow setting up new nearby devices.'
  desc 'This control allows Apple device users to request passwords from nearby devices. This could lead to a compromise of the device password with an unauthorized person or device. DoD Apple device passwords should not be shared.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is Supervised by the MDM, review configuration settings to confirm "Allow setting up new nearby devices" is disabled.

This check procedure is performed on both the iOS/iPadOS device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS/iPadOS management tool, verify "Proximity setup to a new device is not allowed" is unchecked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Proximity setup to a new device is not allowed" is not listed.

If "Proximity setup to a new device is not allowed" is disabled in both the iOS/iPadOS management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the allow setting up new nearby devices in the management tool. This a Supervised only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21115r547681_chk'
  tag severity: 'medium'
  tag gid: 'V-219390'
  tag rid: 'SV-219390r604137_rule'
  tag stig_id: 'AIOS-13-013300'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21114r547682_fix'
  tag 'documentable'
  tag legacy: ['SV-106613', 'V-97509']
  tag cci: ['CCI-000366', 'CCI-000370', 'CCI-000097']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'AC-20 (2)']
end
