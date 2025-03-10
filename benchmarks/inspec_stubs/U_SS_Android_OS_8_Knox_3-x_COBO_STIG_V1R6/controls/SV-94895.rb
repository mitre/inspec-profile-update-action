control 'SV-94895' do
  title 'Samsung Android 8 with Knox must be configured to not display the following notifications when the device is locked: All notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Samsung Android 8 with Knox to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Samsung Android 8 with Knox settings to determine if Samsung Android 8 with Knox displays (work CONTAINER) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Notifications on lock screen" settings in the "Android Restrictions" rule. 
2. Verify that the "Hide content" or "Do not show notification" setting is enabled and "Show content" setting is disabled.

On the Samsung Android 8 with Knox device, do the following:
1. Lock the device while there are notifications shown in the notification bar.
2. Turn the display on and verify that notification contents are hidden ("Hide content") or that no notifications are shown ("Do not show notification") on the lock screen.

In the MDM console, if "Show content" is enabled and the Samsung Android 8 with Knox device allows notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to not display (work CONTAINER) notifications when the device is locked.

On the MDM console, enable "Hide content" or "Do not show notification" in the "Notifications on lock screen" setting in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79863r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80191'
  tag rid: 'SV-94895r1_rule'
  tag stig_id: 'KNOX-08-007300'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-86997r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
