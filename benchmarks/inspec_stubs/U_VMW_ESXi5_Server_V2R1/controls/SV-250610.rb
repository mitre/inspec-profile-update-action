control 'SV-250610' do
  title 'The system must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface. Firewire devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', "If the system uses IEEE 1394, this is not applicable.

To verify hardware enabled options: Interrupt the host computer's boot process and enter the BIOS menu.  Inspect the menu option for IEEE 1394 device connectivity.

If the system does not use IEEE 1394 and IEEE 1394 is enabled, this is a finding."
  desc 'fix', "To modify hardware enabled options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for IEEE 1394 device connectivity.  Disable IEEE 1394."
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54045r798827_chk'
  tag severity: 'low'
  tag gid: 'V-250610'
  tag rid: 'SV-250610r798829_rule'
  tag stig_id: 'GEN008500-ESXI5-000123'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53999r798828_fix'
  tag 'documentable'
  tag legacy: ['SV-51107', 'V-39291']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
