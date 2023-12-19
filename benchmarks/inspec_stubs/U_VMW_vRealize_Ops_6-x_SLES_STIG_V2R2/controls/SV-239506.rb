control 'SV-239506' do
  title 'The SLES for the vRealize boot loader configuration file(s) must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 on boot loader configuration files could allow an unauthorized user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'check', 'Check the /boot/grub/menu.lst file:

# stat /boot/grub/menu.lst

If "/boot/grub/menu.lst" has a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Change the mode of the "/boot/grub/menu.lst" file to "0600":

# chmod 0600 /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42739r661967_chk'
  tag severity: 'medium'
  tag gid: 'V-239506'
  tag rid: 'SV-239506r661969_rule'
  tag stig_id: 'VROM-SL-000425'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-42698r661968_fix'
  tag 'documentable'
  tag legacy: ['SV-99133', 'V-88483']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
