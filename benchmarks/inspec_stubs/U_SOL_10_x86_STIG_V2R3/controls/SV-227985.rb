control 'SV-227985' do
  title "The system's boot loader configuration file(s) must have mode 0600 or less permissive."
  desc 'File permissions greater than 0600 on boot loader configuration files could allow an unauthorized user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Check the permission of the menu.lst file.

On systems that have a ZFS root, the menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the menu.lst file is typically located at /boot/grub/menu.lst .  

Procedure:
# ls -lL /pool-name/boot/grub/menu.lst 
or
# ls -lL /boot/grub/menu.lst 

If menu.lst has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the menu.lst file to 0600.

# chmod 0600 /pool-name/boot/grub/menu.lst 
or
# chmod 0600 /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30147r490405_chk'
  tag severity: 'medium'
  tag gid: 'V-227985'
  tag rid: 'SV-227985r854522_rule'
  tag stig_id: 'GEN008720'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30135r490406_fix'
  tag 'documentable'
  tag legacy: ['V-4250', 'SV-4250']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
