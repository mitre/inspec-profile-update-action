control 'SV-230086' do
  title 'The Motorola Android Pie must be configured to not display the following (work profile) notifications when the device is locked: [selection:

- email notifications; 
- calendar appointments; 
- contact associated with phone call notification; 
- text message notification; 
- other application-based notifications; 
- all notifications].'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Motorola Android device to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Motorola Android device settings to determine if the Motorola Android device displays (work container) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console: 
1. Open Restrictions section.
2. Open Work Managed section.
3. Verify "Unredacted Notifications" is set to "Disallow".

On the Android Pie device: 
1. Go to Settings >> Security & location.
2. Tap on "Lock screen preferences".
3. Verify "Hide sensitive work content" is listed under "When work profile is locked".

If the MDM console device policy allows work notifications on the lock screen or the Android Pie device allows work notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to not display (work profile) notifications when the device is locked.

On the MDM console: 
1. Open Restrictions section.
2. Open Work Managed section.
3. Set "Unredacted Notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Motorola Android 9.x COPE STIG'
  tag check_id: 'C-32401r538254_chk'
  tag severity: 'medium'
  tag gid: 'V-230086'
  tag rid: 'SV-230086r569708_rule'
  tag stig_id: 'MOTO-09-001600'
  tag gtitle: 'GOOG-09-001600'
  tag fix_id: 'F-32379r538255_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
