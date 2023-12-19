control 'SV-237009' do
  title 'Google Android 10 must be configured to not display the following (work profile) notifications when the device is locked: [selection: - email notifications - calendar appointments - contact associated with phone call notification - text message notification - other application-based notifications - all notifications].'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Google Android device to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Google Android device settings to determine if the Google Android device displays (work container) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the MDM Administration Console and the Android 10 device. 

On the MDM console, do the following:

1. Open restrictions Section.
2. Open Work Managed Section.
3. Ensure "Disable Unredacted Notifications" is selected.

On the Android 10 device, do the following:

1. Go to Settings >> Display >> Advanced. 
2. Tap on Lock screen display.
3. Ensure "Hide sensitive work content" is listed under "When work profile is locked".

If the MDM console device policy allows work notifications on the lock screen, or the Android 10 device allows work notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Google Android device to not display (work profile) notifications when the device is locked.

On the MDM console:

1. Open restrictions section.
2. Open Work Managed Section.
3. Select "Disable Unredacted Notifications".'
  impact 0.5
  ref 'DPMS Target Google Android 10-x'
  tag check_id: 'C-40228r639171_chk'
  tag severity: 'medium'
  tag gid: 'V-237009'
  tag rid: 'SV-237009r639173_rule'
  tag stig_id: 'GOOG-10-001600'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-40191r639172_fix'
  tag 'documentable'
  tag legacy: ['SV-108043', 'V-98939']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
