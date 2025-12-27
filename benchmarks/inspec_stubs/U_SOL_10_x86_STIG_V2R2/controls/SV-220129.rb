control 'SV-220129' do
  title "The system's boot loader configuration file(s) must be group-owned by root, bin, sys, or system."
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modifications resulting from improper group ownership may compromise the boot loader configuration."
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

On systems that have a ZFS root, the active menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the active menu.lst file is typically located at /boot/grub/menu.lst.  To locate the active GRUB menu, use the bootadm command with the list-menu option:

# bootadm list-menu

Check the group ownership of the menu.lst file.

Procedure:
# ls -lL /pool-name/boot/grub/menu.lst  
or
# ls -lL /boot/grub/menu.lst 

If the group owner of the file is not root, bin, sys, or system this is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /pool-name/boot/grub/menu.lst 
or
# chgrp root /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21838r490414_chk'
  tag severity: 'medium'
  tag gid: 'V-220129'
  tag rid: 'SV-220129r603266_rule'
  tag stig_id: 'GEN008780'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21837r490415_fix'
  tag 'documentable'
  tag legacy: ['V-22587', 'SV-26989']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
