control 'SV-220127' do
  title "The system's boot loader configuration file(s) must not have extended ACLs."
  desc "File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.  If extended ACLs are present on the system's boot loader configuration file(s), these files may be vulnerable to unauthorized access or modification, which could compromise the system's boot process."
  desc 'check', 'This check applies to the global zone only. Determine the type zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

On systems that have a ZFS root, the active menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the active menu.lst file is typically located at /boot/grub/menu.lst.  To locate the active GRUB menu, use the bootadm command with the list-menu option:

# bootadm list-menu

Check the permissions of the menu.lst file.

Procedure:
# ls -lL /pool-name/boot/grub/menu.lst 
or
# ls -lL /boot/grub/menu.lst

If the permissions of the menu.lst file contain "+", an extended ACL is present, and this is a finding.'
  desc 'fix', 'If the file with the extended ACL resides on a UFS filesystem:
# getfacl /boot/grub/menu.lst 

Remove each ACE from the file. 
# setfacl -r [ACE] /boot/grub/menu.lst 

If the file with the extended ACL resides on a ZFS filesystem: 
# chmod A- /pool-name/boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36434r602905_chk'
  tag severity: 'medium'
  tag gid: 'V-220127'
  tag rid: 'SV-220127r603266_rule'
  tag stig_id: 'GEN008740'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36398r602906_fix'
  tag 'documentable'
  tag legacy: ['V-22585', 'SV-26985']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
