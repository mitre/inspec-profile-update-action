control 'SV-94931' do
  title 'Samsung Android 8 with Knox must implement the management setting: Disable Admin Remove.'
  desc 'DoD policy requires DoD mobile devices to be managed via a mobile device management service. If Admin Remove is not disabled, the mobile device user can remove the Administrator (MDM) from the device.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to Disable Admin Remove.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Allow Admin Remove" check box in the "Android Restrictions" rule. 
2. Verify the check box is not selected.

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Select "Other security settings".
4. Select "Device admin apps".
5. Verify the enterprise MDM agent is on and cannot be turned off.

If the MDM console "Allow Admin Remove" check box is selected or on the Samsung Android 8 with Knox device, "Device Administrators" cannot be turned off, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 8 with Knox to Disable Admin Remove.

On the MDM console, deselect the "Allow Admin Remove" check box in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80227'
  tag rid: 'SV-94931r1_rule'
  tag stig_id: 'KNOX-08-014200'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
