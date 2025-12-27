control 'SV-91333' do
  title 'The Samsung Android 7 with Knox must be configured to lock the container after 15 minutes (or less) of inactivity.'
  desc 'The screen lock timeout must be set to a value that helps protect the device from unauthorized access. Having a too-long timeout would increase the window of opportunity for adversaries who gain physical access to the mobile device through loss, theft, etc. Such devices are much more likely to be in an unlocked state when acquired by an adversary, thus granting immediate access to the data on the mobile device. The maximum timeout period of 15 minutes has been selected to balance functionality and security; shorter timeout periods may be appropriate, depending on the risks posed to the mobile device.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Not Applicable for the COBO use case.

Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to lock the container after "15" minutes (or less) of inactivity. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Maximum Time to Lock" setting in the "Android Knox Container >> Container Password Restrictions" rule. 
2. Verify the value of the setting is the organization-defined value ("15" minutes) or less.

On the Samsung Android 7 with Knox device, do the following:
1. Open the Knox Container.
2. Refrain from using the Knox Container for "15" minutes.
3. Verify the selected value is the organization-defined value ("15" minutes) or less.

If the MDM console "Maximum Time to Lock" is not set to organization-defined value ("15" minutes) or less or on the Samsung Android 7 with Knox device, the Knox Container does not lock after "15" minutes, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to lock the container after "15" minutes (or less) of inactivity.

On the MDM console, set the "Maximum Time to Lock" to the organization-defined value ("15" minutes) in the "Android Knox Container >> Container Password Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76307r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76637'
  tag rid: 'SV-91333r1_rule'
  tag stig_id: 'KNOX-07-912200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
