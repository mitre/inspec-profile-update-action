control 'SV-217808' do
  title 'Samsung Android Workspace must be configured to lock after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate, depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review the Samsung Android Workspace configuration settings to confirm that the Workspace is locked after 15 minutes (or less) of inactivity. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the Workspace, in the "Knox password constraints" group, verify that "maximum time to lock" is set to 15 minutes. 

On the Samsung Android device, do the following: 
1. Tap any app on the "Workspace" App screen. 
2. Refrain from using the device for 15 minutes. 
3. Verify that the device requires the user to enter the Workspace password to access any app on the "Workspace" App screen. 

If on the MDM console "maximum time to lock" is not set to "15" minutes or less, or the Samsung Android Workspace does not lock after 15 minutes, this is a finding. 

Note: If "When screen turns off" is selected in the Samsung Android Workspace setting Workspace >> Auto lock Workspace, the Workspace will not lock until the screen turns off, regardless of the maximum lock timeout.'
  desc 'fix', 'Configure Samsung Android Workspace to lock after 15 minutes (or less) of inactivity. 

On the MDM console, for the Workspace, in the "Knox password constraints" group, set the "maximum time to lock" to 15 minutes.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19024r362882_chk'
  tag severity: 'medium'
  tag gid: 'V-217808'
  tag rid: 'SV-217808r388482_rule'
  tag stig_id: 'KNOX-09-000415'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-19022r362883_fix'
  tag 'documentable'
  tag legacy: ['SV-103963', 'V-93877']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
