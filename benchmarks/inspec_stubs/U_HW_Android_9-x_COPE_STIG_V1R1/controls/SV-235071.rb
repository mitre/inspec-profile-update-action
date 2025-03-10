control 'SV-235071' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to not display the following (work profile) notifications when the device is locked: [selection:

- email notifications 
- calendar appointments 
- contact associated with phone call notification 
- text message notification
- other application-based notifications
- all notifications].'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Honeywell Android device to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Honeywell Android device settings to determine if the Honeywell Android device displays (work container) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the MDM Administration console and the Android Pie device. 

On the MDM console:
1. Open Restrictions section.
2. Open Work Managed Section.
3. Ensure "Unredacted Notifications" is set to "Disallow".

On the Honeywell Android Pie device:
1. Go to Settings >> Security & location.
2. Tap on Lock screen preferences.
3. Ensure "Hide sensitive work content" is listed under "When work profile is locked".

If the MDM console device policy allows work notifications on the lock screen or the Android Pie device allows work notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to not display (work profile) notifications when the device is locked.

On the MDM console:
1. Open Restrictions section.
2. Open Work Managed Section.
3. Set "Unredacted Notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38290r623228_chk'
  tag severity: 'medium'
  tag gid: 'V-235071'
  tag rid: 'SV-235071r626527_rule'
  tag stig_id: 'HONW-09-001600'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-38253r623229_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
