control 'SV-258638' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or, alternately, the use of removable storage media must be disabled.'
  desc "The MOS must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #20, #47d"
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are either enabling data-at-rest protection for removable media or disabling their use.

This requirement is not applicable for devices that do not support removable storage media.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "Mount physical media" is set to "Disallow".

On the Samsung Android device, verify that a microSD card cannot be mounted.

The device should ignore the inserted SD card and no notifications for the transfer of media files should appear, nor should any files be listed using a file browser, such as Samsung My Files.

If on the management tool "Mount physical media" is not set to "Disallow", or on the Samsung Android device a microSD card can be mounted, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to enable data-at-rest protection for removable media, or alternatively, disable their use.

This requirement is not applicable for devices that do not support removable storage media.

On the management tool, in the device restrictions, set "Mount physical media" to "Disallow".

This disables the use of all removable storage, e.g., microSD cards, USB thumb drives, etc.

If the deployment requires the use of microSD cards, Knox Platform for Enterprise (KPE) can be used to allow them in a STIG-approved configuration. In this case, do not configure this policy, and instead replace with KPE policy (innately by the management tool or via Knox Service Plugin [KSP]) "Enforce external storage encryption" with value "enable".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62378r931112_chk'
  tag severity: 'high'
  tag gid: 'V-258638'
  tag rid: 'SV-258638r931114_rule'
  tag stig_id: 'KNOX-14-110130'
  tag gtitle: 'PP-MDF-333100'
  tag fix_id: 'F-62287r931113_fix'
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002235']
  tag nist: ['SC-28', 'AC-6 (10)']
end
