control 'SV-37942' do
  title "The system's boot loader configuration file(s) must have mode 0600 or less permissive."
  desc 'File permissions greater than 0600 on boot loader configuration files could allow an unauthorized user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'check', 'Check /boot/grub/grub.conf permissions:

# ls -lL /boot/grub/grub.conf

If /boot/grub/grub.conf has a mode more permissive than 0600, then this is a finding.

For any bootloader other than GRUB which has been authorized, justified and documented for use on the system refer to the vendor documentation for the location of the configuration file. If the bootloader configuration file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the grub.conf file to 0600.

# chmod 0600 /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4250'
  tag rid: 'SV-37942r1_rule'
  tag stig_id: 'GEN008720'
  tag gtitle: 'GEN008720'
  tag fix_id: 'F-32433r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
