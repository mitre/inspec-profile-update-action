control 'SV-84739' do
  title 'Windows 10 Mobile must not allow a USB mass storage mode.'
  desc 'USB mass storage mode enables the transfer of data and software from one device to another. This software can include malware. When USB mass storage is enabled on a mobile device, it becomes a potential vector for malware and unauthorized data exfiltration. Prohibiting USB mass storage mode mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #39'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the mobile device has a USB mass storage mode and whether it has been disabled. If feasible, use a spare device to determine if this data transfer capability is disabled. 

This procedure is the same as requirement MSWM-10-202608. The procedure only has to be performed once.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device and a locally connected desktop.

On the MDM administration console:

1. Ask the MDM administrator to display the USB connectivity setting.
2. Verify the USB connectivity setting is disabled.

On the Windows 10 Mobile device:

1. Connect device to a desktop (that has USB ports enabled).
2. Launch Windows File Explorer on the desktop or wait for a connection pop-up that asks if you want to display the device.
3. In File Explorer click on "This PC" in the left pane.
4. Verify by looking in the right pane of Windows Explorer that the name of the connected device, which may be "Windows Phone" is not displayed.

If the MDM does not have a compliance policy that disables USB connectivity or if using Windows File Explorer a Windows 10 Mobile device name is shown under "This PC", this is a finding.'
  desc 'fix', 'This procedure is the same as requirement MSWM-10-202608. The procedure only has to be performed once.

Configure the MDM system to require the "Allow USB Connection" policy to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70117'
  tag rid: 'SV-84739r1_rule'
  tag stig_id: 'MSWM-10-290704'
  tag gtitle: 'PP-MDF-201016'
  tag fix_id: 'F-76353r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
