control 'SV-257114' do
  title 'Apple iOS/iPadOS 16 must be configured to not display notifications when the device is locked.'
  desc 'Many mobile devices display notifications on the lock screen so users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #18'
  desc 'check', 'Review configuration settings to confirm "Show Notification Center in Lock screen" is disabled.

This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Show Notification Center in Lock screen" is unchecked.

Alternatively, verify the text "<key>allowLockScreenNotificationsView</key> <false/>" appears in the configuration profile (.mobileconfig file).

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Restrictions".
6. Verify "Notifications view on lock screen not allowed" is present.

If "Show Notification Center in Lock screen" is checked in the Apple iOS/iPadOS management tool, "<key>allowLockScreenNotificationsView</key> <true/>" appears in the configuration profile, or the restrictions policy on the iPhone and iPad does not list "Notifications View on lock screen not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Notification Center from the device lock screen.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 16 BYOAD'
  tag check_id: 'C-60799r904240_chk'
  tag severity: 'medium'
  tag gid: 'V-257114'
  tag rid: 'SV-257114r904242_rule'
  tag stig_id: 'AIOS-16-707500'
  tag gtitle: 'PP-MDF-333080'
  tag fix_id: 'F-60740r904241_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
