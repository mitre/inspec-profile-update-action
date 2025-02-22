control 'SV-231022' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or alternatively, the use of removable storage media must be disabled.'
  desc "The MOS must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #21, #47f"
  desc 'check', 'This requirement is not applicable for devices that do not support removable storage media.

If the mobile device does not support removable media, this requirement is not applicable.

Review Samsung Android configuration settings to determine if the use of removable storage media is disabled.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "SD Card" is set to "Disable".

On the Samsung Android device, verify that a microSD card cannot be mounted.

NOTE: To mount the microSD card, insert it into the SIM/SD car tray in the slot marked "microSD", and push the tray firmly back into the device. The device should ignore the inserted SD card and no notifications for the transfer of media files should appear, nor should any files be listed using a file browser, such as Samsung My Files.

If on the management tool "SD Card" is not set to "Disable", or on the Samsung Android device a microSD card can be mounted, this is a finding.'
  desc 'fix', 'This requirement is not applicable for devices that do not support removable storage media.

Configure Samsung Android to enable data-at-rest protection for removable media, or alternatively, disable the use of removable storage media.

On the management tool, in the device restrictions section, set "SD Card" to "Disable".'
  impact 0.7
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33952r592680_chk'
  tag severity: 'high'
  tag gid: 'V-231022'
  tag rid: 'SV-231022r608683_rule'
  tag stig_id: 'KNOX-11-003600'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-33925r592681_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
