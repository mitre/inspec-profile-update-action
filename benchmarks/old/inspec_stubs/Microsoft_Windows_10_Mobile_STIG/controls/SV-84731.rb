control 'SV-84731' do
  title 'Windows 10 Mobile must not allow backup to locally connected systems.'
  desc 'Data on mobile devices is protected by numerous mechanisms, including user authentication, access control, and cryptography. When the data is backed up to an external system (either locally connected or cloud-based), many if not all of these mechanisms are no longer present. This leaves the backed up data vulnerable to attack. Disabling backup to external systems mitigates this risk.

SFR ID: FMT_SMF_EXT.1.1 #40'
  desc 'check', 'Review Windows 10 Mobile configuration settings to determine if the capability to back up to a locally connected system has been disabled. If feasible, use a spare device and determine if the ability to back up is present, perhaps by attempting a back up to a locally connected machine. 

This procedure is the same as requirement MSWM-10-290704. The procedure only has to be performed once.

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
  desc 'fix', 'This procedure is the same as requirement MSWM-10-290704. The procedure only has to be performed once.

Configure the MDM system to require the "Allow USB Connection" policy to be disabled for Windows 10 Mobile devices. 

Deploy the MDM policy on managed devices.'
  impact 0.5
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70585r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70109'
  tag rid: 'SV-84731r1_rule'
  tag stig_id: 'MSWM-10-202608'
  tag gtitle: 'PP-MDF-201017'
  tag fix_id: 'F-76345r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000097', 'CCI-000366']
  tag nist: ['AC-20 (2)', 'CM-6 b']
end
