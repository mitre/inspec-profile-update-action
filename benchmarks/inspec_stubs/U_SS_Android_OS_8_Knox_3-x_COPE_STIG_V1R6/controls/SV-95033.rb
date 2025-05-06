control 'SV-95033' do
  title 'Samsung Android 8 with Knox must be configured to lock the CONTAINER after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate, depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox CONTAINER configuration settings to determine if the mobile device is configured to lock the CONTAINER after 15 minutes (or less) of inactivity. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM CONTAINER console, do the following:
1. Ask the MDM Administrator to display the "Maximum Time to Lock" setting in the "Password Restrictions" rule. 
2. Verify the value of the setting is the organization-defined value (15 minutes). 

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Refrain from using the Knox CONTAINER for 15 minutes.
3. Verify the device requires the user to enter the CONTAINER unlock password to access the CONTAINER. 

If the MDM console "Maximum Time to Lock" is not set to the organization-required value (15 minutes) or less or on the Samsung Android 8 with Knox device, the Knox CONTAINER does not lock after 15 minutes, this is a finding.

Note: If "When screen turns off" is selected in the Samsung Android 8 with Knox CONTAINER setting "Workspace settings >> Auto lock Workspace", the CONTAINER will not lock until the screen turns off, regardless of the maximum lock timeout.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox CONTAINER to lock the CONTAINER after 15 minutes (or less) of inactivity.

On the MDM CONTAINER console, set the "Maximum Time to Lock" to 15 minutes in the "Password Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-80001r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80329'
  tag rid: 'SV-95033r1_rule'
  tag stig_id: 'KNOX-08-009200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87135r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
