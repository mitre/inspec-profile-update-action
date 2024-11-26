control 'SV-94963' do
  title 'Samsung Android 8 with Knox must be configured to enable encryption for information at rest on removable storage media or alternately, the use of removable storage media must be disabled.'
  desc "Samsung Android 8 with Knox must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #21, #47f"
  desc 'check', %q(If the mobile device does not support removable media, this requirement is Not Applicable (NA). 

Review Samsung Android 8 with Knox configuration settings to determine if data in the mobile device's removable storage media is encrypted. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Storage Encryption" setting in the "Android Security" rule. 
2. Verify the "SD Card Encryption" setting is enabled. 

On the Samsung Android 8 with Knox device, do the following:
1. Open the device settings.
2. Select "Lock screen and security".
3. Insert a MicroSD card into the device.
4. If the MicroSD card is not already encrypted, select "Encrypt SD card". Verify "The security policy restricts use of SD cards that are not encrypted" is displayed.
5. If the MicroSD card is encrypted, verify "Decrypt SD card" is displayed and cannot be selected.

If the specified encryption settings are not set to the appropriate values, this is a finding.)
  desc 'fix', 'Configure Samsung Android 8 with Knox to enable information at rest protection for removable media.

On the MDM console, enable the "External Storage Encryption" setting in the "Android Security" rule.'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COBO use case'
  tag check_id: 'C-79931r1_chk'
  tag severity: 'high'
  tag gid: 'V-80259'
  tag rid: 'SV-94963r1_rule'
  tag stig_id: 'KNOX-08-018500'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-87065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
