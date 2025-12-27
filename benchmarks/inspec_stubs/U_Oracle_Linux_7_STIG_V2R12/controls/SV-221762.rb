control 'SV-221762' do
  title 'The Oracle Linux operating system must not allow removable media to be used as the boot loader unless approved.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).'
  desc 'check', %q(Verify the system is not configured to use a boot loader on removable media.

Note: GRUB 2 reads its configuration from the "/boot/grub2/grub.cfg" file on traditional BIOS-based machines and from the "/boot/efi/EFI/redhat/grub.cfg" file on UEFI machines.

Check for the existence of alternate boot loader configuration files with the following command:

# find / -name grub.cfg
/boot/grub2/grub.cfg

If a "grub.cfg" is found in any subdirectories other than "/boot/grub2" and "/boot/efi/EFI/redhat", ask the System Administrator if there is documentation signed by the ISSO to approve the use of removable media as a boot loader. 

Check that the grub configuration file has the set root command in each menu entry with the following commands:

# grep -cw menuentry /boot/grub2/grub.cfg
1
# grep 'set root' /boot/grub2/grub.cfg
set root=(hd0,1)

If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding.)
  desc 'fix', 'Remove alternate methods of booting the system from removable media or document the configuration to boot from removable media with the ISSO.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23477r858455_chk'
  tag severity: 'medium'
  tag gid: 'V-221762'
  tag rid: 'SV-221762r860864_rule'
  tag stig_id: 'OL07-00-021700'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-23466r419359_fix'
  tag 'documentable'
  tag legacy: ['SV-108367', 'V-99263']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
