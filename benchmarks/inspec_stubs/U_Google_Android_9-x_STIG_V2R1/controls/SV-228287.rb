control 'SV-228287' do
  title 'The Google Android Pie must be configured to not display the following (work profile) notifications when the device is locked: [selection: - email notifications - calendar appointments - contact associated with phone call notification - text message notification - other application-based notifications - all notifications].'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Google Android device to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Google Android device settings to determine if the Google Android device displays (work container) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the MDM Administration Console and the Android Pie device. 

On the MDM console, do the following:

1. Open restrictions Section.
2. Open Work Managed Section.
3. Ensure "Unredacted Notifications" is set to Disallow.

On the Android Pie device, do the following:

1. Go to Settings >> Security & location
2. Tap on Lock screen preferences.
3. Ensure "Hide sensitive work content" is listed under "When work profile is locked".

If the MDM console device policy allows work notifications on the lock screen or the Android Pie device allows work notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Google Android device to not display (work profile) notifications when the device is locked.

On the MDM console:

1. Open restrictions section.
2. Open Work Managed Section.
3. Set "Unredacted Notifications" to Disallow.'
  impact 0.5
  ref 'DPMS Target Google Android 9-x'
  tag check_id: 'C-30520r494928_chk'
  tag severity: 'medium'
  tag gid: 'V-228287'
  tag rid: 'SV-228287r617474_rule'
  tag stig_id: 'GOOG-09-001600'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-30505r494929_fix'
  tag 'documentable'
  tag legacy: ['SV-106427', 'V-97323']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
