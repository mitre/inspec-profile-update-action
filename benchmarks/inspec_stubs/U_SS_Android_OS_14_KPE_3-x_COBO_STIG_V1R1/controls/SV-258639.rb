control 'SV-258639' do
  title 'Samsung Android must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling USB mass storage mode.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify "USB file transfer" has been set to "Disallow".

On the Samsung Android device, from the "USB for file transfer" notification, verify a "File Transfer" is not an option.

If on the management tool "USB file transfer" is not set to "Disallow", or on the Samsung Android device a "File Transfer" is an option, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable USB mass storage mode.

On the management tool, in the device restrictions, set "USB file transfer" to "Disallow".

DeX drag and drop file transfer capabilities will be prohibited, but all other DeX capabilities remain usable.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 14 with Knox 3.x COBO'
  tag check_id: 'C-62379r931115_chk'
  tag severity: 'medium'
  tag gid: 'V-258639'
  tag rid: 'SV-258639r931117_rule'
  tag stig_id: 'KNOX-14-110140'
  tag gtitle: 'PP-MDF-333230'
  tag fix_id: 'F-62288r931116_fix'
  tag 'documentable'
  tag cci: ['CCI-002546']
  tag nist: ['SC-41']
end
