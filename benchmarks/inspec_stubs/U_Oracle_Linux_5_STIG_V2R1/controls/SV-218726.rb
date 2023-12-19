control 'SV-218726' do
  title 'The systems boot loader configuration file(s) must have mode 0600 or less permissive.'
  desc 'File permissions greater than 0600 on boot loader configuration files could allow an unauthorized user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'check', 'Check /boot/grub/grub.conf permissions:

# ls -lL /boot/grub/grub.conf

If /boot/grub/grub.conf has a mode more permissive than 0600, then this is a finding.

For any bootloader other than GRUB which has been authorized, justified and documented for use on the system refer to the vendor documentation for the location of the configuration file. If the bootloader configuration file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the grub.conf file to 0600.

# chmod 0600 /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20201r562948_chk'
  tag severity: 'medium'
  tag gid: 'V-218726'
  tag rid: 'SV-218726r603259_rule'
  tag stig_id: 'GEN008720'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20199r562949_fix'
  tag 'documentable'
  tag legacy: ['V-4250', 'SV-63093']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
