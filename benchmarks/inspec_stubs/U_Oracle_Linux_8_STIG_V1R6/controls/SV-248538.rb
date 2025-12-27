control 'SV-248538' do
  title 'OL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must have a unique name for the grub superusers account when booting into single-user mode and maintenance.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for OL 8 and is designed to require a password to boot into single-user mode or modify the boot menu.
The GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of non-unique superusers names are (root, superuser, unlock, etc.)'
  desc 'check', 'For systems that use BIOS, this is Not Applicable.

Verify that a unique name is set as the "superusers" account:

$ sudo grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
set superusers="[someuniqueUserNamehere]"
export superusers

If "superusers" is identical to any OS account name or is missing a name, this is a finding.'
  desc 'fix', 'Configure the system to replace "root" with a unique name for the grub superusers account.

Edit the /etc/grub.d/01_users file and add or modify the following lines:

set superusers="[someuniqueUserNamehere]"
export superusers
password_pbkdf2 [someuniqueUserNamehere] ${GRUB2_PASSWORD}

Generate a new grub.cfg file with the following command:

$ sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51972r818602_chk'
  tag severity: 'medium'
  tag gid: 'V-248538'
  tag rid: 'SV-248538r818603_rule'
  tag stig_id: 'OL08-00-010141'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-51926r779179_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
