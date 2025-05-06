control 'SV-258329' do
  title 'Apple iOS/iPadOS 17 must be configured to not display notifications when the device is locked.'
  desc 'Many mobile devices display notifications on the lock screen so users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the mobile operating system to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #18'
  desc 'check', 'Review configuration settings to confirm the display of notifications when the device is locked has been disabled. There are two acceptable methods. The first method is preferred.

***Verification Procedure for Method 1:
This check procedure is performed only on the Apple iOS/iPadOS management tool. 

In the Apple iOS/iPadOS management tool, for each managed app, verify the app is configured to disable Notifications preview.

If one or more managed apps are not set to disable notification previews, this is a finding.

***Verification Procedure for Method 2:
This check procedure is performed on both the Apple iOS/iPadOS management tool and the iPhone and iPad. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS/iPadOS management tool, verify "Show Notification Center in Lock screen" is unchecked.

On the iPhone and iPad:
1. Open the Settings app.
2. Tap "General".
3. Tap "VPN & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Restrictions".
6. Verify "Notifications view on lock screen not allowed" is present.

If "Show Notification Center in Lock screen" is checked in the Apple iOS/iPadOS management tool or the restrictions policy on the iPhone and iPad does not list "Notifications View on lock screen not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable the display of notifications when the device is locked.  There are two acceptable methods.  The first method is preferred.

Method 1:
Install a configuration profile to disable notifications for each managed app if the device screen is locked. This method is not supported by all MDM servers.

Method 2:
Install a configuration profile to disable Notification Center from the device Lock screen.'
  impact 0.5
  ref 'DPMS Target Apple iOS-iPadOS 17 STIG'
  tag check_id: 'C-62070r927668_chk'
  tag severity: 'medium'
  tag gid: 'V-258329'
  tag rid: 'SV-258329r927670_rule'
  tag stig_id: 'AIOS-17-007500'
  tag gtitle: 'PP-MDF-333080'
  tag fix_id: 'F-61994r927669_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
