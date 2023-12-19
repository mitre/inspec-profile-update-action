control 'SV-250971' do
  title 'Apple iOS/iPadOS 15 must disable password proximity requests.'
  desc 'This control allows one Apple device to be notified to share its password with a nearby device. This could lead to a compromise of the device password with an unauthorized person or device. DoD Apple device passwords must not be shared.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Allow Password Proximity Requests" is disabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS management tool, verify "Allow Password Proximity Requests" is unchecked.

On the iPhone and iPad device:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Proximity password requests not allowed" is not listed.

If "Proximity password requests not allowed" is not disabled in both the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the allow password proximity requests in the management tool. This a supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 15'
  tag check_id: 'C-54406r802002_chk'
  tag severity: 'medium'
  tag gid: 'V-250971'
  tag rid: 'SV-250971r802004_rule'
  tag stig_id: 'AIOS-15-012900'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-54360r802003_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
