control 'SV-37981' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices with the potential to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system needs USB, this vulnerability is not applicable.
Check if the directory "/proc/bus/usb" exists. If so, this is a finding.'
  desc 'fix', 'Edit the grub bootloader file "/boot/grub/grub.conf" or "/boot/grub/menu.lst" by appending the "nousb" parameter to the kernel boot line.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37280r1_chk'
  tag severity: 'low'
  tag gid: 'V-22578'
  tag rid: 'SV-37981r1_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'GEN008460'
  tag fix_id: 'F-32517r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
