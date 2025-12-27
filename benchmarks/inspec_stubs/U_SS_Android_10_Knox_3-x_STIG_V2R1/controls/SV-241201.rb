control 'SV-241201' do
  title 'Samsung Android must be configured to not display the following (Work Environment) notifications when the device is locked: all notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Samsung Android configuration settings to determine if Samsung Android displays (Work Environment) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: Disable unredacted notifications on the Keyguard (COBO or COPE).

On the management tool, in the Work Environment restrictions section, verify that "Unredacted Notifications" is set to "Disallow".

For COPE: On the Samsung Android device, do the following:
1. Open Settings >> Work profile >> Notification and data.
2. Verify that "Show notification content" is disabled.

For COBO: On the Samsung Android device, do the following:
1. Open Settings >> Lock screen.
2. Verify that "Notifications" are disabled.

If on the management tool "Unredacted Notifications" is not set to "Disallow", or on the Samsung Android device "Show notification content" is not disabled, this is a finding.

****

Method #2: Use KPE notification sanitization for notifications (COPE only).

On the management tool, in the Work Environment KPE RCP section, verify that "Show detailed notifications" is set to "Disallow".

On the Samsung Android device, do the following:
1. Open Settings >> Work profile >> Notification and data.
2. Verify that "Show notification content" is disabled.

If on the management tool "Show detailed notifications" is not set to "Disallow", or on the Samsung Android device "Show notification content" is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to not display (Work Environment) notifications when the device is locked.

Do one of the following:
- Method #1: Disable unredacted notifications on the Keyguard (COBO or COPE).
- Method #2: Use KPE notification sanitization for notifications (COPE only).

****

Method #1: Disable unredacted notifications on the Keyguard (COBO or COPE).

On the management tool, in the Work Environment restrictions section, set "Unredacted Notifications" to "Disallow".

****

Method #2: Use KPE notification sanitization for notifications (COPE only).

On the management tool, in the Work Environment KPE RCP section, set "Show detailed notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44477r680242_chk'
  tag severity: 'medium'
  tag gid: 'V-241201'
  tag rid: 'SV-241201r916595_rule'
  tag stig_id: 'KNOX-10-001500'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-44436r680243_fix'
  tag 'documentable'
  tag legacy: ['SV-109035', 'V-99931']
  tag cci: ['CCI-000366', 'CCI-000051']
  tag nist: ['CM-6 b', 'AC-8 a']
end
