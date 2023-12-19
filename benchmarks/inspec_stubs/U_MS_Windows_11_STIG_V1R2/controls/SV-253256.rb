control 'SV-253256' do
  title 'Windows 11 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.'
  desc 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows 11, including virtualization-based Security and Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode will not support these security features.'
  desc 'check', 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.'
  desc 'fix', 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56709r828850_chk'
  tag severity: 'medium'
  tag gid: 'V-253256'
  tag rid: 'SV-253256r828852_rule'
  tag stig_id: 'WN11-00-000015'
  tag gtitle: 'SRG-OS-000424-GPOS-00188'
  tag fix_id: 'F-56659r828851_fix'
  tag 'documentable'
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
