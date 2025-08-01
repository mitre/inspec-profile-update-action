control 'SV-93081' do
  title 'Apple iOS must not display notifications (calendar information) when the device is locked.'
  desc 'Many mobile devices display notifications (including calendar information) on the lock screen so users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

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
5. Verify "Today view on lock screen not allowed" is present.

If the "Show Today view in Lock screen" is checked in the Apple iOS management tool, "<key>allowLockScreenTodayView</key><true/>" appears in the configuration profile, or the restrictions policy on the Apple iOS device from the Apple iOS management tool does not list "Today view on lock screen not allowed", this is a finding.'
  desc 'fix', 'Install a configuration profile to disable Notification Center from the device Lock screen.'
  impact 0.5
  ref 'DPMS Target Apple iOS 11'
  tag check_id: 'C-77937r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78375'
  tag rid: 'SV-93081r1_rule'
  tag stig_id: 'AIOS-11-001800'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-85107r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
