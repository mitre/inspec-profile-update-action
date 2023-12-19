control 'SV-220128' do
  title "The system's boot loader configuration files must be owned by root."
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

On systems that have a ZFS root, the active menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the active menu.lst file is typically located at /boot/grub/menu.lst.  To locate the active GRUB menu, use the bootadm command with the list-menu option:

# bootadm list-menu
 
Check the ownership of the menu.lst file.

Procedure:
# ls -lL /pool-name/boot/grub/menu.lst  
or
# ls -lL /boot/grub/menu.lst 

If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the ownership of the file.
# chown root /pool-name/boot/grub/menu.lst 
or
# chown root /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21837r490411_chk'
  tag severity: 'medium'
  tag gid: 'V-220128'
  tag rid: 'SV-220128r603266_rule'
  tag stig_id: 'GEN008760'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21836r490412_fix'
  tag 'documentable'
  tag legacy: ['V-22586', 'SV-26987']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
