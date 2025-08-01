control 'SV-218714' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices with the potential to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system needs USB, this vulnerability is not applicable.
Check if the directory "/proc/bus/usb" exists. If so, this is a finding.'
  desc 'fix', 'Edit the grub bootloader file "/boot/grub/grub.conf" or "/boot/grub/menu.lst" by appending the "nousb" parameter to the kernel boot line.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20189r556559_chk'
  tag severity: 'low'
  tag gid: 'V-218714'
  tag rid: 'SV-218714r603259_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20187r556560_fix'
  tag 'documentable'
  tag legacy: ['V-22578', 'SV-63189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
