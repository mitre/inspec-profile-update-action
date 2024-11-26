control 'SV-217666' do
  title 'Samsung Android must be configured to not display the following notifications when the device is locked: all notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the mobile operating system to redact the contents of the notifications when the device is locked mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review device configuration settings to confirm that the content of notifications is redacted when the device is locked. 

This procedure is performed on both the MDM console and the Samsung Android device. 

On the MDM console, for the device, in the "Android lock screen restrictions" group, verify that "disable unredacted notifications" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Lock screen". 
3. Verify that "Notifications" is disabled. 

If on the MDM console "disable unredacted notifications" is not selected, or on the Samsung Android device "Notifications" is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android to redact notifications when the device is locked. 

On the MDM console, for the device, in the "Android lock screen restrictions" group, select "disable unredacted notifications".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18885r362027_chk'
  tag severity: 'medium'
  tag gid: 'V-217666'
  tag rid: 'SV-217666r617474_rule'
  tag stig_id: 'KNOX-09-000280'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-18883r362028_fix'
  tag 'documentable'
  tag legacy: ['SV-102957', 'V-92869']
  tag cci: ['CCI-000051', 'CCI-000366']
  tag nist: ['AC-8 a', 'CM-6 b']
end
