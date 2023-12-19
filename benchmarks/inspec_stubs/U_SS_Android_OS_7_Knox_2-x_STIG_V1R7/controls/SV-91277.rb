control 'SV-91277' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Disable USB host storage.'
  desc 'The USB host storage feature allows the device to connect to select USB devices (e.g., USB flash drives, USB mouse, USB keyboard) using a micro USB to USB adapter cable. A user can copy sensitive DoD information to external USB storage unencrypted, resulting in compromise of DoD data. Disabling this feature mitigates the risk of compromising sensitive DoD data. USB host storage is automatically disabled in the Knox container.

Note: USB host storage must be enabled in the personal space/container in order to use the DeX Station.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to disable USB host storage.

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 7 with Knox device.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Allow USB host storage" checkbox in the "Android Restrictions" rule. 
2. Verify the checkbox is not selected.

On the Samsung Android 7 with Knox device, do the following:
1. Connect a Micro USB to USB OTG adaptor to the device.
2. Connect a USB thumb drive to the adaptor.
3. Verify the device cannot access the USB thumb drive.

If the MDM console "Allow USB host storage" checkbox is selected or on the Samsung Android 7 with Knox device the user is able to access the USB thumb drive from the device, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to disable USB host storage.

On the MDM console, deselect the "Allow USB host storage" checkbox in the "Android Restrictions" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76249r3_chk'
  tag severity: 'medium'
  tag gid: 'V-76581'
  tag rid: 'SV-91277r1_rule'
  tag stig_id: 'KNOX-07-012600'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83275r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
