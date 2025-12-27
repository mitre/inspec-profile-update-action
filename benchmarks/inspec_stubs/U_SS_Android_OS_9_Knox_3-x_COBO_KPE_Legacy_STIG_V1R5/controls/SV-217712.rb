control 'SV-217712' do
  title 'Samsung Android must be configured to lock the display after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #2b'
  desc 'check', 'Review device configuration settings to confirm that the device locks the screen after 15 minutes (or less) of inactivity. 

This procedure is performed on both the MDM Administration Console and the Samsung Android device. 

On the MDM console, in the Android lock screen restrictions, verify that the "max time to screen lock" is "15" minutes or less. 

On the Samsung Android device, do the following: 
1. Unlock the device. 
2. Refrain from performing any activity on the device for 15 minutes. 
3. Verify that the device requires the user to enter the device unlock password to access the device. 

If on the MDM console "max time to lock" is not set to "15" minutes or less, or the Samsung Android device does not require the user to authenticate to unlock after 15 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure Samsung Android to lock the device display after 15 minutes (or less) of inactivity. 

On the MDM console, for the device, in the "Android lock screen restrictions" group, set the "max time to screen lock" to "15" minutes.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18930r362284_chk'
  tag severity: 'medium'
  tag gid: 'V-217712'
  tag rid: 'SV-217712r378598_rule'
  tag stig_id: 'KNOX-09-000405'
  tag gtitle: 'PP-MDF-301040'
  tag fix_id: 'F-18928r362285_fix'
  tag 'documentable'
  tag legacy: ['SV-103671', 'V-93585']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
