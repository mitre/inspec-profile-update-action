control 'SV-217722' do
  title 'Samsung Android must be configured to enforce a USB host mode exception list. Note: This configuration allows DeX mode (with input devices), which is DoD-approved for use.'
  desc 'The USB host mode feature allows USB devices to connect to the device (e.g., USB flash drives, USB mouse, USB keyboard) using a micro USB-to-USB adapter cable. The USB host mode exception list allows selected USB devices to operate while disallowing others based on their USB device class. 

With some USB device classes, a user can copy sensitive DoD information to external USB storage unencrypted, resulting in compromise of DoD data. However, some USB device classes, such as Human Interface Devices (HID), do not allow data to be copied. 

Disabling all USB devices except for HID mitigates the risk of compromising sensitive DoD data. 

This allows for DeX mode to be used with a USB keyboard and mouse without compromising DoD data.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review device configuration settings to confirm that the USB host mode exception list is configured. 

This procedure is performed on both the MDM Administration console and the Samsung Android device. 

On the MDM console, for the device, in the "Knox restrictions" group, verify that "USB host mode exception list" is set with "HID". 

On the Samsung Android device, do the following: 
1. Connect a micro USB-to-USB "On the Go" (OTG) adapter to the device. 
2. Connect a USB thumb drive to the adapter. 
3. Verify that the device cannot access the USB thumb drive. 

If on the MDM console "USB host mode exception list" has any selection other than "HID", or on the Samsung Android device the USB thumb drive can be mounted, this is a finding.'
  desc 'fix', 'Configure Samsung Android with a USB host mode exception list. 

On the MDM console, for the device, in the "Knox restrictions" group, select "HID" in the "USB host mode exception list".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE Legacy'
  tag check_id: 'C-18940r362314_chk'
  tag severity: 'medium'
  tag gid: 'V-217722'
  tag rid: 'SV-217722r388482_rule'
  tag stig_id: 'KNOX-09-000755'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18938r362315_fix'
  tag 'documentable'
  tag legacy: ['SV-103691', 'V-93605']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
