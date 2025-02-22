control 'SV-237245' do
  title 'Apple iOS must not display notifications (calendar information) when the device is locked.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review configuration settings to confirm "Show Today view in Lock screen" is disabled.

This check procedure is performed on both the Apple iOS management tool and the Apple iOS device. 

Note: If an organization has multiple configuration profiles, the check procedure must be performed on the relevant configuration profiles applicable to the scope of the review. 

In the Apple iOS management tool, verify "Show Today view in Lock screen" is unchecked.

Alternatively, verify the text "<key>allowLockScreenTodayView</key><false/>" appears in the configuration profile (.mobileconfig file).

On the Apple iOS device: 
1. Open the Settings app. 
2. Tap "General".
3. Tap "Profiles & Device Management".
4. Tap the Configuration Profile from the iOS management tool containing the management policy.
5. Tap "Restrictions".
6. Verify "Today view on lock screen not allowed" is present.

If the "Show Today view in Lock screen" is checked in the Apple iOS management tool, "<key>allowLockScreenTodayView</key><true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Today view on lock screen not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Notification Center from the device Lock screen.'
  impact 0.5
  ref 'DPMS Target Apple iOS 12'
  tag check_id: 'C-40464r642285_chk'
  tag severity: 'medium'
  tag gid: 'V-237245'
  tag rid: 'SV-237245r852616_rule'
  tag stig_id: 'AIOS-12-001900'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-40427r642286_fix'
  tag 'documentable'
  tag legacy: ['SV-96487', 'V-81773']
  tag cci: ['CCI-000366', 'CCI-001806']
  tag nist: ['CM-6 b', 'CM-11 b']
end
