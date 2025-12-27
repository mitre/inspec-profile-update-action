control 'SV-239508' do
  title 'The SLES for the vRealize boot loader configuration file(s) must be group-owned by root, bin, sys, or system.'
  desc 'The SLES for vRealize’s boot loader configuration files are critical to the integrity of the system and must be protected. Unauthorized modifications resulting from improper group ownership may compromise the boot loader configuration.'
  desc 'check', 'Check "/boot/grub/menu.lst" file ownership:

# stat /boot/grub/menu.lst

If the group-owner of the file is not "root", "bin", "sys", or "system", this is a finding.'
  desc 'fix', 'Change the group-ownership of the "/boot/grub/menu.lst" file:

# chgrp root /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42741r661973_chk'
  tag severity: 'medium'
  tag gid: 'V-239508'
  tag rid: 'SV-239508r661975_rule'
  tag stig_id: 'VROM-SL-000435'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-42700r661974_fix'
  tag 'documentable'
  tag legacy: ['SV-99137', 'V-88487']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
