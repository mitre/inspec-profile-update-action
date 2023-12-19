control 'SV-258364' do
  title 'Apple iOS/iPadOS 17 must disable password proximity requests.'
  desc 'This control allows one Apple device to be notified to share its password with a nearby device. This could lead to a compromise of the device password with an unauthorized person or device. DOD Apple device passwords must not be shared.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Allow Password Proximity Requests" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow Password Proximity Requests" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Proximity password requests not allowed" is listed.

If "Proximity password requests not allowed" is not listed in the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable "allow password proximity requests" in the management tool. This is a supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62105r935482_chk'
  tag severity: 'medium'
  tag gid: 'V-258364'
  tag rid: 'SV-258364r935484_rule'
  tag stig_id: 'AIOS-17-012900'
  tag gtitle: 'PP-MDF-993300'
  tag fix_id: 'F-62029r935483_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
