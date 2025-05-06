control 'SV-250609' do
  title 'The system must have USB Mass Storage disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', "If the system uses USB mass storage, this is not applicable.

To verify hardware enabled options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for USB mass storage connectivity.

If the system does not require USB mass storage and USB mass storage connectivity is enabled, this is a finding."
  desc 'fix', "To modify hardware enabled options: Interrupt the host computer's boot process and enter the BIOS menu. Inspect the menu option for USB mass storage connectivity.  Disable USB mass storage connectivity."
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54044r798824_chk'
  tag severity: 'low'
  tag gid: 'V-250609'
  tag rid: 'SV-250609r798826_rule'
  tag stig_id: 'GEN008480-ESXI5-000122'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53998r798825_fix'
  tag 'documentable'
  tag legacy: ['V-39289', 'SV-51105']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
