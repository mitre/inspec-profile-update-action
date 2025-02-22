control 'SV-252425' do
  title 'Samsung Android must be configured to not display the following (Work Environment) notifications when the device is locked: all notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #18'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are not displaying (Work Environment) notifications when the device is locked.

Notifications of incoming phone calls are acceptable even when the device is locked.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the Work profile restrictions section, verify that "Unredacted Notifications" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Work profile >> Notification and data.
2. Verify that "Show notification content" is disabled.

If on the management tool "Unredacted Notifications" is not set to "Disallow", or on the Samsung Android device "Show notification content" is not disabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to not display (Work Environment) notifications when the device is locked.

On the management tool, in the Work profile restrictions section, set "Unredacted Notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55881r815486_chk'
  tag severity: 'medium'
  tag gid: 'V-252425'
  tag rid: 'SV-252425r815488_rule'
  tag stig_id: 'KNOX-12-210200'
  tag gtitle: 'PP-MDF-323080'
  tag fix_id: 'F-55831r815487_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
