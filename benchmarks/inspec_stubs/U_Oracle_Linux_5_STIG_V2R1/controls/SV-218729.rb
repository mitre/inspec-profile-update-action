control 'SV-218729' do
  title 'The systems boot loader configuration file(s) must be group-owned by root, bin, sys, or system.'
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modifications resulting from improper group ownership may compromise the boot loader configuration."
  desc 'check', 'Check the group ownership of the file.
# ls -lLd /boot/grub/grub.conf
If the group-owner of the file is not root, bin, sys, or system this is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20204r562957_chk'
  tag severity: 'medium'
  tag gid: 'V-218729'
  tag rid: 'SV-218729r603259_rule'
  tag stig_id: 'GEN008780'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20202r562958_fix'
  tag 'documentable'
  tag legacy: ['V-22587', 'SV-63069']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
