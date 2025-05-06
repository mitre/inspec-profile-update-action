control 'SV-219391' do
  title 'Apple iOS/iPadOS must disable password proximity requests.'
  desc 'This control allows one Apple device to be notified to share its password with a nearby device. This could lead to a compromise of the device password with an unauthorized person or device. DoD Apple device passwords should not be shared.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a Supervised-only control. If the iPhone or iPad being reviewed is not Supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is Supervised by the MDM, review configuration settings to confirm "Allow Password Proximity Requests" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, then the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow Password Proximity Requests" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles" or "Profiles & Device Management" or "Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Proximity password requests not allowed" is not listed.

If "Proximity password requests not allowed" is not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the allow password proximity requests in the management tool. This a Supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 13'
  tag check_id: 'C-21116r547684_chk'
  tag severity: 'medium'
  tag gid: 'V-219391'
  tag rid: 'SV-219391r604137_rule'
  tag stig_id: 'AIOS-13-013400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-21115r547685_fix'
  tag 'documentable'
  tag legacy: ['SV-106615', 'V-97511']
  tag cci: ['CCI-000097', 'CCI-000370', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 (1)', 'CM-6 b']
end
