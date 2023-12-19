control 'SV-228731' do
  title 'The mobile operating system must be configured to enable a screen-lock policy that will lock the display after a period of inactivity.'
  desc 'The screen-lock timeout helps protect the device from unauthorized access. Devices without a screen-lock timeout provide an opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device and possibly access to DoD networks.

'
  desc 'check', 'Review configuration settings to confirm the screen lock timeout is set to 15 minutes or less.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad.

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review.

In the management tool, verify the sum of the values assigned to "Maximum Auto-Lock time" and "Grace period for device lock" is between 1 and 15 minutes. 

Alternatively, locate the text "<key>maxGracePeriod</key>" and "<key>maxInactivity</key>" and ensure the sum of their integer value is between 1 and 15 in the configuration profile (.mobileconfig file). For example:

"<key>maxGracePeriod</key>
<integer>5</integer>
<key>maxInactivity</key>
<integer>5</integer>"

Here, 5 + 5 = 10; this meets the requirement.

On the iPhone and iPad: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management" or "Profiles".
4. Tap the Configuration Profile from the iOS management tool containing the password policy.
5. Tap "Restrictions".
6. Tap "Passcode".
7. Verify the sum of the "Max grace period" and "Max inactivity" values is less than 15 minutes.

Note: On some iOS/iPadOS devices, it is not possible to have a sum of exactly 15. In these cases, the sum must be less than 15. A sum of 16 does not meet the requirement.

On the management server, if the sum of the "Max grace period" and "Max inactivity" values is not between 1 and 15 minutes in the iOS/iPadOS management tool; or if the sum of the values assigned to "<key>maxGracePeriod</key>" and "<key>maxInactivity</key>" is not between 1 and 15 minutes in the configuration profile; or if on the iPhone/iPad, the sum of the values assigned to "Max grace period" and "Max inactivity" is not between 1 and 15 minutes, this is a finding.'
  desc 'fix', 'Install a configuration profile to lock the device display after 15 minutes (or less) of inactivity. This is done by setting "Maximum Auto-Lock time" and "Grace Period for device lock" so the sum of their values is between 1 and 15 minutes.'
  impact 0.5
  ref 'DPMS Target Apple iOS iPadOS 14'
  tag check_id: 'C-30966r509821_chk'
  tag severity: 'medium'
  tag gid: 'V-228731'
  tag rid: 'SV-228731r561031_rule'
  tag stig_id: 'AIOS-14-000300'
  tag gtitle: 'PP-MDF-301030'
  tag fix_id: 'F-30943r509822_fix'
  tag satisfies: ['PP-MDF-301030', 'PP-MDF-301040\n\nSFR ID: FMT_SMF_EXT.1.1 #2a & #2b']
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
