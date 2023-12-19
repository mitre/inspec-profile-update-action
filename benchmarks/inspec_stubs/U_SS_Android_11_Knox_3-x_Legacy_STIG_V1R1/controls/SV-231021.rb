control 'SV-231021' do
  title 'Samsung Android must be configured to not display the following (Work Environment) notifications when the device is locked: all notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the MOS to not send notifications to the lock screen mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review Samsung Android configuration settings to determine if Samsung Android displays (Work Environment) notifications on the lock screen. Notifications of incoming phone calls are acceptable even when the device is locked. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

This procedure is only applicable to the COPE use case.

On the management tool, in the Work Environment RCP section, verify that "Show detailed notifications" is set to "Disallow".

On the COPE Samsung Android device:
1. Open Settings >> Work profile >> Notification and data.
2. Verify that "Show notification content" is disabled.

If on the management tool "Show detailed notifications" is not set to "Disallow", or on the Samsung Android device "Show notification content" is not disabled, this is a finding.

NOTE: For the COBO use case, the API to implement this policy has been impacted by DA deprecation, and no KPE alternative policy is available. If the device is deployed in COBO mode, this requirement is not met and is a permanent finding.'
  desc 'fix', 'Configure Samsung Android to not display (Work Environment) notifications when the device is locked.

This guidance is only applicable to the COPE use case.

On the management tool, in the Work Environment RCP section, set "Show detailed notifications" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33951r592677_chk'
  tag severity: 'medium'
  tag gid: 'V-231021'
  tag rid: 'SV-231021r608683_rule'
  tag stig_id: 'KNOX-11-002800'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-33924r592678_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000051']
  tag nist: ['CM-6 b', 'AC-8 a']
end
