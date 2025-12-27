control 'SV-91239' do
  title 'The Samsung Android 7 with Knox must be configured to not display the following notifications when the device is locked: All notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the Samsung Android 7 with Knox to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Not Applicable if the AO has approved unmanaged personal space/container (COPE use case). The site must have an AO signed document showing the AO has assumed the risk for using an unmanaged personal container.

Review Samsung Android 7 with Knox settings to determine if the Samsung Android 7 with Knox displays notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Notifications on lock screen" settings in the "Android Restrictions" rule. 
2. Verify that the "Hide content" or "Do not show notification" setting is enabled and "Show content" setting is disabled.

On the Samsung Android 7 with Knox device, do the following:
1. Lock the device while there are notifications shown in the notification bar.
2. Turn the display on and verify that notification contents are hidden ("Hide content") or that no notifications are shown ("Do not show notification") on the lock screen.

If on the MDM console "Show content" is enabled and the Samsung Android 7 with Knox device allows notifications on the lock screen, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to not display notifications when the device is locked.

On the MDM console, enable "Hide content" or "Do not show notification" in the "Notifications on lock screen" setting in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76203r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76543'
  tag rid: 'SV-91239r1_rule'
  tag stig_id: 'KNOX-07-002600'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-83225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
