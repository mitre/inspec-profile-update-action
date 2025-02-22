control 'SV-254773' do
  title 'Google Android 13 must be configured to not display the following (work profile) notifications when the device is locked: [selection:

a. email notifications 
b. calendar appointments 
c. contact associated with phone call notification 
d. text message notification
e. other application-based notifications
f. all notifications].'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the mobile operating system (MOS) to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #18'
  desc 'check', 'Review managed Google Android 13 device settings to determine if the Google Android 13 device displays (work profile) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the EMM Administration Console and the managed Google Android 13 device. 

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Verify that "Disable unredacted notifications" is toggled to "ON".

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Work Profile".
4. Verify that "Disable unredacted notifications" is toggled to "ON".
___________________________

On the managed Google Android 13 device:

COBO:

1. Go to Settings >> Display >> Lock screen.
2. Tap on "Privacy".
3. Verify that "Show sensitive content only when unlocked" is selected.

COPE:

1. Go to Settings >> Display >> Lock screen.
2. Tap on "When work profile is locked".
3. Verify that "Hide sensitive work content" is selected.

If the EMM console device policy allows work notifications on the lock screen, or the managed Google Android 13 device allows work notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Google Android 13 device to not display (work profile) notifications when the device is locked.

On the EMM console:

COBO:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Toggle "Disable unredacted notifications".

COPE:

1. Open "Lock screen" settings.
2. Open "Lock screen restrictions".
3. Select "Work Profile".
4. Toggle "Disable unredacted notifications".'
  impact 0.5
  ref 'DPMS Target Google Android 13 COPE'
  tag check_id: 'C-58384r862699_chk'
  tag severity: 'medium'
  tag gid: 'V-254773'
  tag rid: 'SV-254773r862701_rule'
  tag stig_id: 'GOOG-13-006800'
  tag gtitle: 'PP-MDF-323080'
  tag fix_id: 'F-58330r862700_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
