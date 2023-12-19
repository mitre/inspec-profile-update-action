control 'SV-255119' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or, alternately, the use of removable storage media must be disabled.'
  desc "The MOS must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #20, #47d"
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are either enabling data at rest protection for removable media, or are disabling their use.

This requirement is not applicable for devices that do not support removable storage media.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "Mount physical media" is set to "Disallow".

On the Samsung Android device, verify that a microSD card cannot be mounted.

The device should ignore the inserted SD card and no notifications for the transfer of media files should appear, nor should any files be listed using a file browser, such as Samsung My Files.

If on the management tool "Mount physical media" is not set to "Disallow", or on the Samsung Android device a microSD card can be mounted, this is a finding.

If the deployment requires the use of micro SD cards, follow this alternative procedure:

On the management tool,  in the device restrictions, verify "Enforce external storage encryption" is set to "Enable".

On the Samsung Android device, do the following:
1. Insert a freshly formatted microSD card.
2. Verify that a prompt appears to encrypt the microSD card.
3. Perform the encryption.
4. Remove and reinsert the microSD card and verify that a notification appears stating that the mounted microSD card is encrypted.

If on the management tool "External storage encryption" is not set to "Enable", or on the Samsung Android device a microSD card can be used without first being encrypted, this is a finding'
  desc 'fix', 'Configure the Samsung Android devices to enable data at rest protection for removable media, or alternatively, disable their use.

This requirement is not applicable for devices that do not support removable storage media.

On the management tool, in the device restrictions, set "Mount physical media" to "Disallow".

This disables the use of all removable storage, e.g., micro SD cards, USB thumb drives, etc.

If the deployment requires the use of micro SD cards, KPE can be used to allow its usage in a STIG-approved configuration. In this case, do not configure the policy above, and instead:

On the management tool,  in the device restrictions, set "Enforce external storage encryption" to "enable".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58732r873662_chk'
  tag severity: 'high'
  tag gid: 'V-255119'
  tag rid: 'SV-255119r873664_rule'
  tag stig_id: 'KNOX-13-110130'
  tag gtitle: 'PP-MDF-323100'
  tag fix_id: 'F-58676r873663_fix'
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002235']
  tag nist: ['SC-28', 'AC-6 (10)']
end
