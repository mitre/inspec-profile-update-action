control 'SV-252418' do
  title 'Samsung Android must be configured to disable USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39'
  desc 'check', 'Review the configuration to determine if the Samsung Android devices are disabling USB mass storage mode.

This validation procedure is performed on both the management tool and the Samsung Android device.

On the management tool, in the device restrictions, verify that "USB file transfer" has been set to "Disallow".

On the PC, browse the mounted Samsung Android device and verify that it does not display any folders or files.

If on the management tool "USB file transfer" is not set to "Disallow", or the PC can mount and browse folders and files on the Samsung Android device, this is a finding.'
  desc 'fix', 'Configure the Samsung Android devices to disable USB mass storage mode.

On the management tool, in the device restrictions, set "USB file transfer" to "Disallow".

DeX drag & drop file transfer capabilities will be prohibited, but all other DeX capabilities remain useable.'
  impact 0.5
  ref 'DPMS Target Samsung Android 12 KPE 3.x COPE'
  tag check_id: 'C-55874r815465_chk'
  tag severity: 'medium'
  tag gid: 'V-252418'
  tag rid: 'SV-252418r815467_rule'
  tag stig_id: 'KNOX-12-210130'
  tag gtitle: 'PP-MDF-323230'
  tag fix_id: 'F-55824r815466_fix'
  tag 'documentable'
  tag cci: ['CCI-002546']
  tag nist: ['SC-41']
end
