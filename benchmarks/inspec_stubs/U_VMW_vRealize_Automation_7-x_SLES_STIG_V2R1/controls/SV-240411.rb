control 'SV-240411' do
  title 'The system boot loader configuration file(s) must be group-owned by root, bin, sys, or system.'
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected. Unauthorized modifications resulting from improper group-ownership may compromise the boot loader configuration."
  desc 'check', 'Check /boot/grub/menu.lst ownership:

# stat /boot/grub/menu.lst

If the group-owner of the file is not "root", "bin", "sys", or "system", this is a finding.'
  desc 'fix', 'Change the group-ownership of the file:

# chgrp root /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43644r670972_chk'
  tag severity: 'medium'
  tag gid: 'V-240411'
  tag rid: 'SV-240411r670974_rule'
  tag stig_id: 'VRAU-SL-000440'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-43603r670973_fix'
  tag 'documentable'
  tag legacy: ['SV-100249', 'V-89599']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
