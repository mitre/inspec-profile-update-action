control 'SV-255127' do
  title 'Samsung Android must be configured to not display the following (Work Environment) notifications when the device is locked: All notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #18'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are not displaying (Work Environment) notifications when the device is locked.

Notifications of incoming phone calls are acceptable even when the device is locked.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "Unredacted Notifications" is set to "Disallow".

On the Samsung Android device: 
1. Open Settings >> Lock screen.
2. Verify that "Notifications" menu is disabled.

If on the management tool "Unredacted Notifications" is not set to "Disallow", or on the Samsung Android device "Notifications" menu is not disabled, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to not display (Work Environment) notifications when the device is locked.

On the management tool, in the device restrictions section, set "Unredacted Notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58740r867316_chk'
  tag severity: 'medium'
  tag gid: 'V-255127'
  tag rid: 'SV-255127r867318_rule'
  tag stig_id: 'KNOX-13-110210'
  tag gtitle: 'PP-MDF-323080'
  tag fix_id: 'F-58684r867317_fix'
  tag 'documentable'
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end
