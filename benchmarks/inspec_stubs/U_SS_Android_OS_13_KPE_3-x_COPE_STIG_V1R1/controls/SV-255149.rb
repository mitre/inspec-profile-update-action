control 'SV-255149' do
  title 'Samsung Android must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling USB mass storage mode.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "USB file transfer" has been set to "Disallow".

On the Samsung Android device, from the USB settings notification, verify that a "File Transfer" is not an option.

If on the management tool "USB file transfer" is not set to "Disallow", or on the Samsung Android device a "File Transfer" is an option, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable USB mass storage mode.

On the management tool, in the device restrictions, set "USB file transfer" to "Disallow".

DeX drag and drop file transfer capabilities will be prohibited, but all other DeX capabilities remain useable.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58762r867382_chk'
  tag severity: 'medium'
  tag gid: 'V-255149'
  tag rid: 'SV-255149r867384_rule'
  tag stig_id: 'KNOX-13-210140'
  tag gtitle: 'PP-MDF-323230'
  tag fix_id: 'F-58706r867383_fix'
  tag 'documentable'
  tag cci: ['CCI-002546']
  tag nist: ['SC-41']
end
