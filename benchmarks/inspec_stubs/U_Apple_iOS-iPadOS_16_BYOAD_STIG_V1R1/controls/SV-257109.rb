control 'SV-257109' do
  title 'Apple iOS/iPadOS 16 must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DOD networks.

SFR ID: FMT_SMF_EXT.1.1 #2a'
  desc 'check', 'Review configuration settings to confirm the screen lock timeout is set to 15 minutes or less.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

For User Enrollment, check a sample of user phones to verify compliance:
1. Open "Settings".
2. Tap "Display & Brightness".
3. Tap "Auto-Lock".
4. Verify "Auto-Lock" has been set to "5 minutes" or less. 

For Device Enrollment, in the management tool, verify the sum of the values assigned to "Maximum Auto-Lock time" and "Grace period for device lock" is between 1 and 15 minutes. 

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify the sum of the "Max grace period" and "Max inactivity" values is less than 15 minutes.

Note: On some iOS/iPadOS devices, it is not possible to have a sum of exactly 15. In these cases, the sum must be less than 15. A sum of 16 does not meet the requirement.

For User Enrollment, if on sampled Apple devices the Auto-Lock is not set to 5 minutes or less, this is a finding.

For Device Enrollment, on the management server, if the sum of the "Max grace period" and "Max inactivity" values is not between 1 and 15 minutes in the iOS/iPadOS management tool or if on the iPhone/iPad, the sum of the values assigned to "Max grace period" and "Max inactivity" is not between 1 and 15 minutes, this is a finding.'
  desc 'fix', 'For User Enrollment, this is a User-Based Enforcement (UBE) control. The device user must configure setting on their personal phone.
1. Open "Settings".
2. Tap "Display & Brightness".
3. Tap "Auto-Lock". 
4. Set "Auto-Lock" to "5 minutes" or less.

For Device Enrollment, install a configuration profile to lock the device display after 15 minutes (or less) of inactivity. This is done by setting "Maximum Auto-Lock time" and "Grace Period for device lock" so the sum of their values is between 1 and 15 minutes.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60794r904225_chk'
  tag severity: 'medium'
  tag gid: 'V-257109'
  tag rid: 'SV-257109r904227_rule'
  tag stig_id: 'AIOS-16-706700'
  tag gtitle: 'PP-MDF-333026'
  tag fix_id: 'F-60735r904226_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
