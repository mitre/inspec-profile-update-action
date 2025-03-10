control 'SV-231027' do
  title 'Samsung Android must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39a'
  desc 'check', 'Review Samsung Android configuration settings to determine if the mobile device has a USB mass storage mode and if it has been disabled. 

This validation procedure is performed on both the management tool Administration Console and the Samsung Android device.

On the management tool, in the device restrictions section, verify that "USB file transfer" has been set to "Disallow".

On the PC, browse the mounted Samsung Android device and verify that it does not display any folders or files.

If on the management tool "USB file transfer" is not set to "Disallow", or the PC can mount and browse folders and files on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure Samsung Android to disable USB mass storage mode.

On the management tool, in the device restrictions section, set "USB file transfer" to "Disallow".'
  impact 0.5
  ref 'DPMS Target Samsung Android 11 Knox 3.x Legacy'
  tag check_id: 'C-33957r592695_chk'
  tag severity: 'medium'
  tag gid: 'V-231027'
  tag rid: 'SV-231027r608683_rule'
  tag stig_id: 'KNOX-11-006600'
  tag gtitle: 'PP-MDF-301210'
  tag fix_id: 'F-33930r592696_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
