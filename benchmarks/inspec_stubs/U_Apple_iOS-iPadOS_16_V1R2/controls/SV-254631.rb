control 'SV-254631' do
  title 'Apple iOS/iPadOS 16 must disable password sharing.'
  desc 'This control allows sharing passwords between Apple devices using AirDrop. This could lead to a compromise of the device password with an unauthorized person or device. DoD Apple device passwords must not be shared.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'This a supervised-only control. If the iPhone or iPad being reviewed is not supervised by the MDM, this control is automatically a finding.

If the iPhone or iPad being reviewed is supervised by the MDM, review configuration settings to confirm "Password Sharing is not allowed" is enabled.

This check procedure is performed on both the device management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the iOS/iPadOS management tool, verify "Password Sharing is not allowed" is checked.

On the iPhone/iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the restrictions policy.
5. Tap "Restrictions".
6. Verify "Password Sharing is not allowed" is listed.

If "Password Sharing is not allowed" is not enabled in the management tool and on the Apple device, this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the allow password proximity sharing in the management tool. This a supervised-only control.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16'
  tag check_id: 'C-58242r862147_chk'
  tag severity: 'medium'
  tag gid: 'V-254631'
  tag rid: 'SV-254631r862219_rule'
  tag stig_id: 'AIOS-16-013000'
  tag gtitle: 'PP-MDF-990000'
  tag fix_id: 'F-58188r862148_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000097', 'CCI-000370']
  tag nist: ['CM-6 b', 'AC-20 (2)', 'CM-6 (1)']
end
