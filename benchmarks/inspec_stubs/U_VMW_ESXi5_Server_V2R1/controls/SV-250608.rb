control 'SV-250608' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', "If the system uses USB, this is not applicable.

To verify hardware enabled options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for USB device connectivity. 

If the system does not require USB and USB is enabled, this is a finding."
  desc 'fix', "To modify hardware enabled options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for USB device connectivity. Disable USB."
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54043r798821_chk'
  tag severity: 'low'
  tag gid: 'V-250608'
  tag rid: 'SV-250608r798823_rule'
  tag stig_id: 'GEN008460-ESXI5-000121'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53997r798822_fix'
  tag 'documentable'
  tag legacy: ['SV-51104', 'V-39288']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
