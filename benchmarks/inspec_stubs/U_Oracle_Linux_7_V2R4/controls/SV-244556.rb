control 'SV-244556' do
  title 'Oracle Linux operating systems version 7.2 or newer booted with United Extensible Firmware Interface (UEFI) must have a unique name for the grub superusers account when booting into single-user mode and maintenance.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for Oracle Linux 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use BIOS, this is Not Applicable.

For systems that are running a version of Oracle Linux prior to 7.2, this is Not Applicable.
Verify that a unique name is set as the "superusers" account:

$ sudo grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
set superusers="[someuniquestringhere]"
export superusers

If "superusers" is not set to a unique name or is missing a name, this is a finding.'
  desc 'fix', 'Configure the system to require a grub bootloader password for the grub superusers account.

Edit the /boot/efi/EFI/redhat/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="[someuniquestringhere]"
export superusers
password_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-47831r744058_chk'
  tag severity: 'medium'
  tag gid: 'V-244556'
  tag rid: 'SV-244556r744060_rule'
  tag stig_id: 'OL07-00-010492'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-47788r744059_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
