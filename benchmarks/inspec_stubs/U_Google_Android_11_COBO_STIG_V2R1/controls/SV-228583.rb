control 'SV-228583' do
  title 'Google Android 11 must be configured to not display the following (work profile) notifications when the device is locked: [selection:- email notifications - calendar appointments - contact associated with phone call notification - text message notification- other application-based notifications- all notifications].'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Google Android device to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Google Android device settings to determine if the Google Android device displays (work container) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the EMM Administration Console and the Android 11 device. 

On the EMM console, do the following:
1. Open "Lock screen restrictions" section.
2. Select "Work Profile".
3. Verify that "Disable Unredacted Notifications" is toggled to On.

On the Android 11 device, do the following:
1. Go to Settings >> Display >> Advanced. 
2. Tap on Lock screen display.
3. Ensure "Hide sensitive work content" is listed under "When work profile is locked".

If the EMM console device policy allows work notifications on the lock screen, or the Android 11 device allows work notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Google Android 11 device to not display (work profile) notifications when the device is locked.

On the EMM console:
1. Open "Lock screen restrictions" section.
2. Select "Work Profile".
3. Toggle "Disable Unredacted Notifications".'
  impact 0.5
  ref 'DPMS Target Google Android 11 COBO'
  tag check_id: 'C-30818r505574_chk'
  tag severity: 'medium'
  tag gid: 'V-228583'
  tag rid: 'SV-228583r619923_rule'
  tag stig_id: 'GOOG-11-001600'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-30795r505575_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000051']
  tag nist: ['CM-6 b', 'AC-8 a']
end
