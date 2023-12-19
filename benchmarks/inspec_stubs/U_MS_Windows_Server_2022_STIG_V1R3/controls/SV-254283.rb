control 'SV-254283' do
  title 'Windows Server 2022 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.'
  desc 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows, including Virtualization Based Security and Credential Guard. Systems with UEFI that are operating in "Legacy BIOS" mode will not support these security features.'
  desc 'check', 'Devices that have UEFI firmware must run in "UEFI" mode.

Verify the system firmware is configured to run in "UEFI" mode, not "Legacy BIOS".

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.'
  desc 'fix', 'Configure UEFI firmware to run in "UEFI" mode, not "Legacy BIOS" mode.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57768r848663_chk'
  tag severity: 'medium'
  tag gid: 'V-254283'
  tag rid: 'SV-254283r848665_rule'
  tag stig_id: 'WN22-00-000460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57719r848664_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
