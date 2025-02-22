control 'SV-258646' do
  title 'Samsung Android must be configured to not display the following (Work Environment) notifications when the device is locked: All notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #18'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are not displaying (Work Environment) notifications when the device is locked.

Notifications of incoming phone calls are acceptable even when the device is locked.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify "Unredacted Notifications" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Notifications.
2. Verify "Lock screen notifications" menu is disabled.

If on the management tool "Unredacted Notifications" is not set to "Disallow", or on the Samsung Android device "Notifications" menu is not disabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to not display (Work Environment) notifications when the device is locked.

On the management tool, in the device restrictions section, set "Unredacted Notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62386r931136_chk'
  tag severity: 'medium'
  tag gid: 'V-258646'
  tag rid: 'SV-258646r931138_rule'
  tag stig_id: 'KNOX-14-110210'
  tag gtitle: 'PP-MDF-333080'
  tag fix_id: 'F-62295r931137_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
