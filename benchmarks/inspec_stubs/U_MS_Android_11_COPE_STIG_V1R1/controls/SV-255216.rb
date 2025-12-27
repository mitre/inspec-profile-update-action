control 'SV-255216' do
  title 'Microsoft Android 11 must be configured to not allow backup of [all applications, configuration data] to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed-up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the capability to back up to a locally connected system has been disabled. 

This validation procedure is performed on both the EMM Administration console and the Android 11 device. 

On the EMM console:
1. Open "Device owner management" section.
2. Verify that "Enable backup service" is toggled to "Off".
3. Open "User restrictions on parent".
4. Verify that "Disallow usb file transfer" is toggled to "On".

On the Microsoft Android 11 device:
1. Plug a USB cable into Android 11 device and connect to a non-DOD network-managed PC. 
2. Go to Settings >> Connected devices >> USB.
3. Ensure “No data transfer" is selected.

If the EMM console device policy is not set to disable the capability to back up to a locally connected system or on the Android 11 device, the device policy is not set to disable the capability to back up to a locally connected system, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to disable backup to locally connected systems.

Note: On Restrictions, the backup features for Android are not in the framework.

On the EMM console:
1. Open "Device owner management" section.
2. Toggle "Enable backup service" to "Off".
3. Open "User restrictions on parent".
4. Select "Disallow usb file transfer".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COPE'
  tag check_id: 'C-58829r870749_chk'
  tag severity: 'medium'
  tag gid: 'V-255216'
  tag rid: 'SV-255216r870829_rule'
  tag stig_id: 'MSFT-11-003700'
  tag gtitle: 'PP-MDF-301220'
  tag fix_id: 'F-58773r869264_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
