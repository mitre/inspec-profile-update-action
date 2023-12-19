control 'SV-255122' do
  title 'Samsung Android must be configured to enable authentication of personal hotspot connections to the device using a pre-shared key.'
  desc 'If no authentication is required to establish personal hotspot connections, an adversary may be able to use that device to perform attacks on other devices or networks without detection. A sophisticated adversary may also be able to exploit unknown system vulnerabilities to access information and computing resources on the device. Requiring authentication to establish personal hotspot connections mitigates this risk.

Application note: If hotspot functionality is permitted, it must be authenticated via a preshared key. There is no requirement to enable hotspot functionality, and it is recommended this functionality be disabled by default.

SFR ID: FMT_SMF_EXT.1.1 #41'
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
  desc 'fix', %q(Configure the Samsung Android devices to enable authentication of personal hotspot connections to the device using a pre-shared key.

On the management tool, in the device restrictions, set "Configure tethering" to "Disallow".

If the deployment requires the use of Mobile Hotspot and Tethering, KPE policy can be used to allow its usage in a STIG-approved configuration. In this case, do not configure the policy above, and instead:

On the management tool, in the device Wi-Fi section, set "Unsecured hotspot" to "Disallow" and add Training Topic "Don't use Wi-Fi Sharing" (see supplemental document for additional information).)
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COBO'
  tag check_id: 'C-58735r873665_chk'
  tag severity: 'medium'
  tag gid: 'V-255122'
  tag rid: 'SV-255122r873667_rule'
  tag stig_id: 'KNOX-13-110160'
  tag gtitle: 'PP-MDF-323260'
  tag fix_id: 'F-58679r873666_fix'
  tag 'documentable'
  tag cci: ['CCI-001443', 'CCI-002314']
  tag nist: ['AC-18 (1)', 'AC-17 (1)']
end
