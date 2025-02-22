control 'SV-221700' do
  title 'Oracle Linux operating systems version 7.2 or newer with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for Oracle Linux 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use BIOS, this is Not Applicable.

For systems that are running a version of Oracle Linux prior to 7.2, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use UEFI, use the following command:

# grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the root password does not begin with "grub.pbkdf2.sha512", this is a finding.

Verify that the "root" account is set as the "superusers":

# grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
set superusers="root"
export superusers

If "superusers" is not set to "root" this is a finding.'
  desc 'fix', 'Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub2-setpassword
Enter password:
Confirm password:

Edit the /boot/grub2/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="root"
export superusers'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23415r419172_chk'
  tag severity: 'high'
  tag gid: 'V-221700'
  tag rid: 'SV-221700r603260_rule'
  tag stig_id: 'OL07-00-010482'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-23404r419173_fix'
  tag 'documentable'
  tag legacy: ['SV-108243', 'V-99139']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
