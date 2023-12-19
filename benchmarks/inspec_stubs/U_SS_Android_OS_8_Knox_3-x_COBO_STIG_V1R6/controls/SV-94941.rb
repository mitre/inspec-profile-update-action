control 'SV-94941' do
  title 'Samsung Android 8 with Knox must implement the management setting: USB host mode whitelist.'
  desc 'The USB host mode feature allows select USB devices to connect to the device (e.g., USB flash drives, USB mouse, USB keyboard) using a micro USB to USB adapter cable. A user can copy sensitive DoD information to external USB storage unencrypted, resulting in compromise of DoD data. Disabling this feature mitigates the risk of compromising sensitive DoD data. 

Note: The USB HID host must be whitelisted in order to use the DeX Station.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to disable USB host modes.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the “USB exception list” setting in the “Android Restrictions” rule.
2. Verify only the HID USB class is selected.

On the Samsung Android 8 with Knox device, do the following:
1. Connect a Micro USB to USB OTG adapter to the device.
2. Connect a USB thumb drive to the adapter.
3. Verify the device cannot access the USB thumb drive.

If the MDM console “USB exception list” setting has non-HID USB classes selected or on the Samsung Android 8 with Knox device, the user is able to access the USB thumb drive from the device, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to disable USB host modes.

On the MDM console, select the HID USB class in the “USB host mode exception list” setting in the “Android Restrictions” rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80237'
  tag rid: 'SV-94941r1_rule'
  tag stig_id: 'KNOX-08-015700'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87043r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
