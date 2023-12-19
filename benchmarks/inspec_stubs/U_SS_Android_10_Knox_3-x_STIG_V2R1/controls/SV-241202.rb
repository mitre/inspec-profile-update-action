control 'SV-241202' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or alternatively, the use of removable storage media must be disabled.'
  desc "The MOS must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #21, #47f"
  desc 'check', 'If the mobile device does not support removable media, this requirement is not applicable.

Review Samsung Android configuration settings to determine if data in the mobile device is removable storage media is encrypted, or alternatively, the use of removable storage media is disabled.

Confirm if Method #1 or #2 is used at the Samsung device site and follow the appropriate procedure.

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

****

Method #1: Disable SD card (if not using SD card).

On the management tool, in the device restrictions section, verify that "SD Card" is set to "Disable".

On the Samsung Android device, verify that a Micro SD card cannot be mounted.

If on the management tool "SD Card" is not set to "Disable", or on the Samsung Android device a microSD card can be mounted, this is a finding.

****

Method #2: Enable data-at-rest protection.

On the management tool, in the device KPE encryption section, verify that "External storage encryption" is set to "Enable".

On the Samsung Android device, do the following:
1. Insert a freshly formatted microSD card.
2. Verify that a prompt appears to encrypt the microSD card.
3. Perform the encryption.
4. Remove and reinsert the microSD card and verify that a notification appears stating that the mounted microSD card is encrypted.

If on the management tool "External storage encryption" is not set to "Enable", or on the Samsung Android device a microSD card can be used without first being encrypted, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable data-at-rest protection for removable media, or alternatively, disable the use of removable storage media.

Do one of the following:
- Method #1: Disable SD card (if not using SD card).
- Method #2: Enable data-at-rest protection.

****

Method #1: Disable SD card (if not using SD card).

On the management tool, in the device restrictions section, set "SD Card" to "Disable".

****

Method #2: Enable data-at-rest protection.

On the management tool, in the device KPE encryption section, set "External storage encryption" to "Enable".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 10 with Knox 3-x'
  tag check_id: 'C-44478r680245_chk'
  tag severity: 'high'
  tag gid: 'V-241202'
  tag rid: 'SV-241202r680247_rule'
  tag stig_id: 'KNOX-10-001900'
  tag gtitle: 'PP-MDF-301140'
  tag fix_id: 'F-44437r680246_fix'
  tag 'documentable'
  tag legacy: ['SV-109037', 'V-99933']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
