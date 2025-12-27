control 'SV-217752' do
  title 'Samsung Android Workspace must be configured to not display the following notifications when the device is locked: all notifications.'
  desc 'Many mobile devices display notifications on the lock screen so that users can obtain relevant information in a timely manner without having to frequently unlock the phone to determine if there are new notifications. However, in many cases, these notifications can contain sensitive information. When they are available on the lock screen, an adversary can see them merely by being in close physical proximity to the device. Configuring the mobile operating system to redact the contents of the notifications when the device is locked mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #19'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that the content of Workspace notifications is redacted when the device is locked. 

This procedure is performed on both the MDM console and the Samsung Android device. 

On the MDM console, for the Workspace, in the "Android lock screen restrictions" group, verify that "disable unredacted notification" is selected. 

On the Samsung Android device, do the following: 
1. Open Settings. 
2. Tap "Workspace". 
3. Tap "Notification and data". 
4. Verify that "Show notification content" is disabled. 

If on the MDM console "disable unredacted notifications" is not selected, or on the Samsung Android device "Show notification content" is not disabled, this is a finding.'
  desc 'fix', 'Configure Samsung Android Workspace to redact the content of Workspace notifications when the device is locked. 

On the MDM console, for the Workspace, in the "Android lock screen restrictions" group, select "disable unredacted notifications".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE AE'
  tag check_id: 'C-18969r362549_chk'
  tag severity: 'medium'
  tag gid: 'V-217752'
  tag rid: 'SV-217752r617474_rule'
  tag stig_id: 'KNOX-09-000300'
  tag gtitle: 'PP-MDF-301120'
  tag fix_id: 'F-18967r362550_fix'
  tag 'documentable'
  tag legacy: ['SV-103853', 'V-93767']
  tag cci: ['CCI-000051', 'CCI-000366']
  tag nist: ['AC-8 a', 'CM-6 b']
end
