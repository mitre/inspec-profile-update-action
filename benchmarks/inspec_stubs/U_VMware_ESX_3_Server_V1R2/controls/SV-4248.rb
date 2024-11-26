control 'SV-4248' do
  title 'For systems capable of using GRUB, the system must be configured with GRUB as the default boot loader unless another boot loader has been authorized, justified, and documented using site-defined procedures.'
  desc 'GRUB is a versatile boot loader used by several platforms providing authentication for access to the system or boot loader.'
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

On systems that have a ZFS root, the active menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the active menu.lst file is typically located at /boot/grub/menu.lst.  To locate the active GRUB menu, use the bootadm command with the list-menu option:

# bootadm list-menu

Determine if the system uses the GRUB boot loader.

Procedure:
# more /pool-name/boot/grub/menu.lst 
or
# more /boot/grub/menu.lst 

If menu.lst does not exist, this is a finding.'
  desc 'fix', 'Configure the system to use the GRUB bootloader.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2058r3_chk'
  tag severity: 'high'
  tag gid: 'V-4248'
  tag rid: 'SV-4248r3_rule'
  tag stig_id: 'GEN008660'
  tag gtitle: 'GEN008660'
  tag fix_id: 'F-4159r2_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
